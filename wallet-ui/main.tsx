import ReactDOM from 'react-dom/client'
import WalletApp from './src/App'
import './src/styles.css'

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('Wallet root element not found')
}

ReactDOM.createRoot(rootElement).render(<WalletApp />)
