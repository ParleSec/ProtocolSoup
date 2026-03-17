import ReactDOM from 'react-dom/client'
import WalletApp from '../src/wallet/App'
import '../src/wallet/styles.css'

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('Wallet root element not found')
}

ReactDOM.createRoot(rootElement).render(<WalletApp />)
