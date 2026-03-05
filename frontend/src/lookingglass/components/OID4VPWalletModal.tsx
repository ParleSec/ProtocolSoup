import { motion } from 'framer-motion'
import { Loader2, X } from 'lucide-react'
import { humanizeOID4VPTrustMode } from '../../protocols/config/oid4vp'

export type OID4VPWalletMode = 'one_click' | 'stepwise'
export type OID4VPWalletStep = 'bootstrap' | 'issue_credential' | 'build_presentation' | 'submit_response'

interface OID4VPWalletModalProps {
  onClose: () => void
  submitPending: boolean
  requestID: string
  responseMode: string
  trustMode: string
  requestURI: string
  didWebAllowedHosts: string[]
  walletHandoffPayload: string
  capturedWalletSubject: string
  walletSubjectInput: string
  onWalletSubjectInputChange: (value: string) => void
  onUseCapturedWalletSubject: () => void
  capturedCredentialJWT: string
  credentialJWTInput: string
  onCredentialJWTInputChange: (value: string) => void
  onUseCapturedCredentialJWT: () => void
  disclosureOptions: string[]
  selectedDisclosureClaims: string[]
  onToggleDisclosureClaim: (claimName: string) => void
  walletMode: OID4VPWalletMode
  onWalletModeChange: (mode: OID4VPWalletMode) => void
  onExecuteWalletStep: (step: OID4VPWalletStep) => void
  canSubmitWalletInteraction: boolean
  stepwiseLastStep: string
  stepwiseVPToken: string
  submitError: string | null
  submitMessage: string | null
  onSubmitWalletResponse: () => void
}

export function OID4VPWalletModal({
  onClose,
  submitPending,
  requestID,
  responseMode,
  trustMode,
  requestURI,
  didWebAllowedHosts,
  walletHandoffPayload,
  capturedWalletSubject,
  walletSubjectInput,
  onWalletSubjectInputChange,
  onUseCapturedWalletSubject,
  capturedCredentialJWT,
  credentialJWTInput,
  onCredentialJWTInputChange,
  onUseCapturedCredentialJWT,
  disclosureOptions,
  selectedDisclosureClaims,
  onToggleDisclosureClaim,
  walletMode,
  onWalletModeChange,
  onExecuteWalletStep,
  canSubmitWalletInteraction,
  stepwiseLastStep,
  stepwiseVPToken,
  submitError,
  submitMessage,
  onSubmitWalletResponse,
}: OID4VPWalletModalProps) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm p-3 sm:p-6 flex items-center justify-center"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, y: 12, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 8, scale: 0.98 }}
        transition={{ duration: 0.16 }}
        className="w-full max-w-2xl rounded-xl border border-white/10 bg-surface-900 shadow-2xl overflow-hidden"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="px-4 sm:px-5 py-3 sm:py-4 border-b border-white/10 flex items-center justify-between gap-3">
          <div>
            <h3 className="text-white text-sm sm:text-base font-medium">OID4VP Wallet Interaction</h3>
            <p className="text-[11px] sm:text-xs text-surface-400 mt-0.5">
              Fulfill the wallet step and submit a real presentation callback.
            </p>
          </div>
          <button
            onClick={onClose}
            disabled={submitPending}
            className="p-1.5 rounded-lg text-surface-400 hover:text-white hover:bg-white/5 disabled:opacity-50 transition-colors"
            title="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 sm:p-5 space-y-4 max-h-[75vh] overflow-y-auto">
          <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 space-y-2">
            <div className="text-xs text-cyan-300 font-medium">Request Context</div>
            <div className="grid gap-1 text-[11px] sm:text-xs text-surface-300">
              <div><span className="text-surface-400">request_id:</span> <code>{requestID || 'missing'}</code></div>
              <div><span className="text-surface-400">response_mode:</span> <code>{responseMode || 'direct_post'}</code></div>
              {trustMode && (
                <div>
                  <span className="text-surface-400">trust_mode:</span> <code>{humanizeOID4VPTrustMode(trustMode)}</code>
                </div>
              )}
              {requestURI && (
                <div className="break-all">
                  <span className="text-surface-400">request_uri:</span> <code>{requestURI}</code>
                </div>
              )}
              {didWebAllowedHosts.length > 0 && (
                <div className="break-all">
                  <span className="text-surface-400">did:web allowlist:</span> <code>{didWebAllowedHosts.join(', ')}</code>
                </div>
              )}
            </div>
          </div>

          {!!walletHandoffPayload && (
            <div className="space-y-1">
              <div className="text-[11px] sm:text-xs text-surface-400">Wallet handoff payload</div>
              <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                {walletHandoffPayload}
              </pre>
            </div>
          )}

          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <label className="text-xs sm:text-sm font-medium text-surface-300">wallet_subject (optional)</label>
              {capturedWalletSubject && (
                <button
                  onClick={onUseCapturedWalletSubject}
                  className="text-[11px] sm:text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  Use captured value
                </button>
              )}
            </div>
            <input
              type="text"
              value={walletSubjectInput}
              onChange={(event) => onWalletSubjectInputChange(event.target.value)}
              placeholder="Leave blank to use wallet harness default subject"
              className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <label className="text-xs sm:text-sm font-medium text-surface-300">credential_jwt (optional)</label>
              {capturedCredentialJWT && (
                <button
                  onClick={onUseCapturedCredentialJWT}
                  className="text-[11px] sm:text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  Use captured value
                </button>
              )}
            </div>
            <textarea
              value={credentialJWTInput}
              onChange={(event) => onCredentialJWTInputChange(event.target.value)}
              rows={5}
              placeholder="Paste SD-JWT VC or issuer credential JWT (or leave blank to auto-issue one)"
              className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-[11px] sm:text-xs font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all resize-y"
            />
          </div>

          <div className="space-y-1.5">
            <div className="text-xs sm:text-sm font-medium text-surface-300">Selective disclosure claims</div>
            <p className="text-[11px] sm:text-xs text-surface-400">
              Choose which SD-JWT disclosures to include in the VP response.
            </p>
            <div className="flex flex-wrap gap-2">
              {disclosureOptions.map((claimName) => {
                const selected = selectedDisclosureClaims.includes(claimName)
                return (
                  <button
                    key={claimName}
                    type="button"
                    onClick={() => onToggleDisclosureClaim(claimName)}
                    className={`px-2 py-1 rounded border text-[11px] sm:text-xs transition-colors ${
                      selected
                        ? 'border-violet-500/40 bg-violet-500/20 text-violet-200'
                        : 'border-white/10 bg-surface-900 text-surface-300 hover:text-white'
                    }`}
                  >
                    {claimName}
                  </button>
                )
              })}
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-xs sm:text-sm font-medium text-surface-300">Wallet execution mode</div>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => onWalletModeChange('one_click')}
                className={`px-2.5 py-2 rounded-lg border text-xs transition-colors ${
                  walletMode === 'one_click'
                    ? 'border-violet-500/40 bg-violet-500/15 text-violet-200'
                    : 'border-white/10 bg-surface-900 text-surface-300 hover:text-white'
                }`}
              >
                One-click mode
              </button>
              <button
                type="button"
                onClick={() => onWalletModeChange('stepwise')}
                className={`px-2.5 py-2 rounded-lg border text-xs transition-colors ${
                  walletMode === 'stepwise'
                    ? 'border-violet-500/40 bg-violet-500/15 text-violet-200'
                    : 'border-white/10 bg-surface-900 text-surface-300 hover:text-white'
                }`}
              >
                Stepwise mode
              </button>
            </div>
          </div>

          {walletMode === 'stepwise' && (
            <div className="rounded-lg border border-violet-500/20 bg-violet-500/5 p-3 space-y-2">
              <div className="text-[11px] sm:text-xs text-violet-200 font-medium">Expert stepwise ceremony</div>
              <div className="grid grid-cols-2 gap-2">
                <button type="button" onClick={() => onExecuteWalletStep('bootstrap')} disabled={submitPending} className="px-2 py-1.5 rounded border border-white/10 bg-surface-900 text-[11px] sm:text-xs text-surface-200 hover:text-white disabled:opacity-50">1) Bootstrap wallet</button>
                <button type="button" onClick={() => onExecuteWalletStep('issue_credential')} disabled={submitPending} className="px-2 py-1.5 rounded border border-white/10 bg-surface-900 text-[11px] sm:text-xs text-surface-200 hover:text-white disabled:opacity-50">2) Issue credential</button>
                <button type="button" onClick={() => onExecuteWalletStep('build_presentation')} disabled={!canSubmitWalletInteraction || submitPending} className="px-2 py-1.5 rounded border border-white/10 bg-surface-900 text-[11px] sm:text-xs text-surface-200 hover:text-white disabled:opacity-50">3) Build vp_token</button>
                <button type="button" onClick={() => onExecuteWalletStep('submit_response')} disabled={!canSubmitWalletInteraction || submitPending} className="px-2 py-1.5 rounded border border-white/10 bg-surface-900 text-[11px] sm:text-xs text-surface-200 hover:text-white disabled:opacity-50">4) Submit response</button>
              </div>
              <div className="text-[11px] sm:text-xs text-surface-300">
                Last step: <code>{stepwiseLastStep || 'none'}</code>
                {stepwiseVPToken && ' • vp_token cached'}
              </div>
            </div>
          )}

          {walletMode === 'one_click' && !canSubmitWalletInteraction && (
            <p className="text-[11px] sm:text-xs text-amber-400">
              Missing request context. Re-run OID4VP request creation.
            </p>
          )}
          {walletMode === 'one_click' && canSubmitWalletInteraction && (
            <p className="text-[11px] sm:text-xs text-cyan-300">
              This modal can complete OID4VP-only runs end-to-end. If credential_jwt is empty, wallet bootstrap will run a real OID4VCI issuance to obtain one before submission.
            </p>
          )}
          {walletMode === 'stepwise' && (
            <p className="text-[11px] sm:text-xs text-cyan-300">
              Stepwise mode exposes wallet key/bootstrap, credential issuance, presentation build, and verifier callback as separate actions.
            </p>
          )}
          {!!submitMessage && (
            <p className="text-[11px] sm:text-xs text-cyan-200">{submitMessage}</p>
          )}
          {!!submitError && (
            <p className="text-[11px] sm:text-xs text-red-300">{submitError}</p>
          )}
        </div>

        <div className="px-4 sm:px-5 py-3 border-t border-white/10 flex items-center justify-end gap-2">
          <button
            onClick={onClose}
            disabled={submitPending}
            className="px-3 py-2 rounded-lg bg-surface-800 border border-white/10 text-surface-300 text-xs sm:text-sm hover:text-white disabled:opacity-50 transition-colors"
          >
            Cancel
          </button>
          {walletMode === 'one_click' && (
            <button
              onClick={onSubmitWalletResponse}
              disabled={!canSubmitWalletInteraction || submitPending}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-violet-500/20 border border-violet-500/30 text-violet-200 text-xs sm:text-sm font-medium hover:bg-violet-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {submitPending && <Loader2 className="w-4 h-4 animate-spin" />}
              <span>{submitPending ? 'Submitting...' : 'Submit Wallet Response'}</span>
            </button>
          )}
        </div>
      </motion.div>
    </motion.div>
  )
}
