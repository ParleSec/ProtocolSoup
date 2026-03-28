type ScanDecodeCallback = (decodedText: string) => void
type ScanStatusCallback = (message: string) => void

type ScannerHandle = {
  stop: () => Promise<void>
}

type Html5QrcodeCamera = {
  id: string
  label?: string
}

type Html5QrcodeInstance = {
  start: (
    cameraConfig: string | { facingMode: string | { exact: string } },
    config: { fps: number; qrbox: { width: number; height: number } },
    onScanSuccess: (decodedText: string) => void,
    onScanFailure: (_errorMessage: string) => void,
  ) => Promise<void>
  stop: () => Promise<void>
  clear: () => Promise<void>
}

type Html5QrcodeCtor = {
  new (containerID: string): Html5QrcodeInstance
  getCameras: () => Promise<Html5QrcodeCamera[]>
}

type BarcodeDetectionResult = {
  rawValue?: string
}

type BarcodeDetectorInstance = {
  detect: (source: HTMLVideoElement) => Promise<BarcodeDetectionResult[]>
}

type BarcodeDetectorCtor = new (options?: { formats?: string[] }) => BarcodeDetectorInstance

type WindowWithScannerSupport = Window & {
  Html5Qrcode?: Html5QrcodeCtor
  BarcodeDetector?: BarcodeDetectorCtor
}

const CAMERA_POLL_MS = 200
const HTML5_QRCODE_CANDIDATES = [
  'https://cdn.jsdelivr.net/npm/html5-qrcode@2.3.8/html5-qrcode.min.js',
  'https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/html5-qrcode/2.3.8/html5-qrcode.min.js',
]

function emitStatus(callback: ScanStatusCallback | undefined, message: string): void {
  if (callback) {
    callback(message)
  }
}

function clearContainer(container: HTMLElement): void {
  while (container.firstChild) {
    container.removeChild(container.firstChild)
  }
}

function isLikelyRearCameraLabel(label: string): boolean {
  const normalized = label.toLowerCase()
  if (!normalized) {
    return false
  }
  return normalized.includes('back')
    || normalized.includes('rear')
    || normalized.includes('environment')
    || normalized.includes('world')
    || normalized.includes('traseira')
    || normalized.includes('arriere')
}

function pickPreferredCamera(cameras: Html5QrcodeCamera[]): Html5QrcodeCamera | null {
  if (cameras.length === 0) {
    return null
  }
  const rearCamera = cameras.find((camera) => isLikelyRearCameraLabel(String(camera.label || '')))
  return rearCamera || cameras[0]
}

function ensureContainerID(container: HTMLElement): string {
  if (container.id && container.id.trim()) {
    return container.id.trim()
  }
  const generatedID = `wallet-scanner-${Math.random().toString(36).slice(2, 10)}`
  container.id = generatedID
  return generatedID
}

async function requestNativeCameraStream(): Promise<MediaStream> {
  const attempts: MediaStreamConstraints[] = [
    { audio: false, video: { facingMode: { exact: 'environment' } } },
    { audio: false, video: { facingMode: 'environment' } },
    { audio: false, video: { facingMode: { ideal: 'environment' } } },
  ]
  for (const constraints of attempts) {
    try {
      return await navigator.mediaDevices.getUserMedia(constraints)
    } catch {
      // Try next camera strategy
    }
  }

  try {
    const devices = await navigator.mediaDevices.enumerateDevices()
    const videoDevices = devices.filter((device) => device.kind === 'videoinput')
    const preferredDevice = pickPreferredCamera(
      videoDevices.map((device) => ({ id: device.deviceId, label: device.label })),
    )
    if (preferredDevice?.id) {
      return await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { deviceId: { exact: preferredDevice.id } },
      })
    }
  } catch {
    // Fall through to generic camera request
  }

  return navigator.mediaDevices.getUserMedia({ audio: false, video: true })
}

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const existingScript = document.querySelector(`script[src="${src}"]`) as HTMLScriptElement | null
    if (existingScript) {
      resolve()
      return
    }
    const script = document.createElement('script')
    script.src = src
    script.async = true
    script.onload = () => resolve()
    script.onerror = () => reject(new Error(`Failed to load ${src}`))
    document.head.appendChild(script)
  })
}

export interface WalletScanner {
  start: (container: HTMLElement, onDecoded: ScanDecodeCallback, onStatus?: ScanStatusCallback) => Promise<boolean>
  stop: () => Promise<void>
}

export function createWalletScanner(): WalletScanner {
  let active = false
  let scanner: ScannerHandle | null = null
  let html5Availability: 'unknown' | 'ready' | 'unavailable' = 'unknown'
  let html5LoadingPromise: Promise<boolean> | null = null

  async function stopCurrent(): Promise<void> {
    if (!active || !scanner) {
      return
    }
    const current = scanner
    scanner = null
    active = false
    try {
      await current.stop()
    } catch {
      // Best-effort shutdown only
    }
  }

  async function startNativeScanner(
    container: HTMLElement,
    onDecoded: ScanDecodeCallback,
    onStatus?: ScanStatusCallback,
  ): Promise<boolean> {
    if (typeof window === 'undefined' || !navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== 'function') {
      return false
    }
    const scannerWindow = window as WindowWithScannerSupport

    const BarcodeDetectorImpl = scannerWindow.BarcodeDetector
    if (!BarcodeDetectorImpl) {
      return false
    }

    let detector: BarcodeDetectorInstance
    try {
      detector = new BarcodeDetectorImpl({ formats: ['qr_code'] })
    } catch {
      try {
        detector = new BarcodeDetectorImpl()
      } catch {
        return false
      }
    }

    clearContainer(container)
    const video = document.createElement('video')
    video.setAttribute('playsinline', 'true')
    video.autoplay = true
    video.muted = true
    video.style.width = '100%'
    video.style.height = '100%'
    container.appendChild(video)

    let stream: MediaStream
    try {
      stream = await requestNativeCameraStream()
    } catch (error) {
      clearContainer(container)
      emitStatus(onStatus, `Unable to access camera ${String(error)}`)
      return false
    }

    video.srcObject = stream
    try {
      await video.play()
    } catch {
      // Some browsers still allow scanning even when play() rejects initially
    }

    let frameTimer: number | undefined
    let stopped = false
    let hasDecoded = false

    const stopNative = async (): Promise<void> => {
      stopped = true
      if (frameTimer !== undefined) {
        window.clearTimeout(frameTimer)
        frameTimer = undefined
      }
      stream.getTracks().forEach((track) => {
        try {
          track.stop()
        } catch {
          // no-op
        }
      })
      video.srcObject = null
      clearContainer(container)
    }

    const scanLoop = async (): Promise<void> => {
      if (stopped || hasDecoded) {
        return
      }
      try {
        if (video.readyState >= 2) {
          const codes = await detector.detect(video)
          if (Array.isArray(codes) && codes.length > 0) {
            const rawValue = String(codes[0]?.rawValue || '').trim()
            if (rawValue) {
              hasDecoded = true
              emitStatus(onStatus, 'QR code scanned')
              await stopNative()
              onDecoded(rawValue)
              return
            }
          }
        }
      } catch {
        // Ignore transient decode errors while stream stabilizes
      }
      frameTimer = window.setTimeout(() => {
        void scanLoop()
      }, CAMERA_POLL_MS)
    }

    scanner = { stop: stopNative }
    active = true
    emitStatus(onStatus, 'Scanner active')
    void scanLoop()
    return true
  }

  async function ensureHtml5QrcodeAvailable(): Promise<boolean> {
    if (typeof window === 'undefined') {
      return false
    }
    const scannerWindow = window as WindowWithScannerSupport
    if (scannerWindow.Html5Qrcode) {
      html5Availability = 'ready'
      return true
    }
    if (html5Availability === 'unavailable') {
      return false
    }
    if (html5LoadingPromise) {
      return html5LoadingPromise
    }
    html5LoadingPromise = (async () => {
      for (const src of HTML5_QRCODE_CANDIDATES) {
        try {
          await loadScript(src)
        } catch {
          continue
        }
        if (scannerWindow.Html5Qrcode) {
          html5Availability = 'ready'
          return true
        }
      }
      html5Availability = 'unavailable'
      return false
    })()
    const loaded = await html5LoadingPromise
    html5LoadingPromise = null
    return loaded
  }

  async function startHtml5QrcodeScanner(
    container: HTMLElement,
    onDecoded: ScanDecodeCallback,
    onStatus?: ScanStatusCallback,
  ): Promise<boolean> {
    const html5Loaded = await ensureHtml5QrcodeAvailable()
    const scannerWindow = (typeof window !== 'undefined' ? window : {}) as WindowWithScannerSupport
    if (!html5Loaded || !scannerWindow.Html5Qrcode) {
      return false
    }
    const containerID = ensureContainerID(container)
    const html5Scanner = new scannerWindow.Html5Qrcode(containerID)
    let hasDecoded = false

    const startWithCameraConfig = async (
      cameraConfig: string | { facingMode: string | { exact: string } },
    ): Promise<void> => {
      await html5Scanner.start(
        cameraConfig,
        { fps: 10, qrbox: { width: 260, height: 260 } },
        (decodedText) => {
          if (hasDecoded) {
            return
          }
          hasDecoded = true
          void stopCurrent().finally(() => {
            onDecoded(String(decodedText || ''))
          })
        },
        () => {
          // Ignore transient scan misses
        },
      )
    }

    try {
      await startWithCameraConfig({ facingMode: { exact: 'environment' } })
    } catch {
      try {
        await startWithCameraConfig({ facingMode: 'environment' })
      } catch {
        let cameras: Html5QrcodeCamera[]
        try {
          cameras = await scannerWindow.Html5Qrcode.getCameras()
        } catch (cameraError) {
          emitStatus(onStatus, `Unable to access camera ${String(cameraError)}`)
          return false
        }
        if (!Array.isArray(cameras) || cameras.length === 0) {
          emitStatus(onStatus, 'No camera found on this device')
          return false
        }
        const selectedCamera = pickPreferredCamera(cameras)
        if (!selectedCamera?.id) {
          emitStatus(onStatus, 'No compatible camera found')
          return false
        }
        try {
          await startWithCameraConfig(selectedCamera.id)
        } catch (cameraStartError) {
          emitStatus(onStatus, `Failed to start scanner ${String(cameraStartError)}`)
          return false
        }
      }
    }

    scanner = {
      stop: async () => {
        try {
          await html5Scanner.stop()
        } catch {
          // no-op
        }
        try {
          await html5Scanner.clear()
        } catch {
          // no-op
        }
      },
    }
    active = true
    emitStatus(onStatus, 'Scanner active')
    return true
  }

  return {
    start: async (container, onDecoded, onStatus) => {
      await stopCurrent()
      const nativeStarted = await startNativeScanner(container, onDecoded, onStatus)
      if (nativeStarted) {
        return true
      }
      const html5Started = await startHtml5QrcodeScanner(container, onDecoded, onStatus)
      if (html5Started) {
        return true
      }
      emitStatus(
        onStatus,
        'QR scanner unavailable in this browser use paste mode or open wallet.protocolsoup.com on a mobile device',
      )
      return false
    },
    stop: async () => {
      await stopCurrent()
    },
  }
}
