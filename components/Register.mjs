import Component from "./Component.mjs";

export default class Register extends Component {
  constructor(props) {
    super(props);
  }

  async render(element) {
    await super.render(element);
    this.container = this.div('container');
    this.container.innerHTML = `
            <h1>Welcome to ${location.hostname}</h1>
            <p>This is a private wiki that uses <a href="https://rootz.global">Rootz</a> data wallets for access and origin.
            <p>Your browser presents a crypotographic address to the server. If you have a web3 plugin installed
            you can select an existing address, otherwise an address will be created in your browser accessible only to this domain.</p>
            <p>Your address is <span id="address">${window.epistery.wallet.address}</span>.</p>
            
            <p>To see behind the site, visit <a href="/.well-known/epistery/status">/.well-known/epistery/status</a></p>

            <div id="request-section">
                <h2>Request Access</h2>
                <p>You can request access by providing a message to the administrator. This could be a promo code,
                   an introduction, or any information that helps identify you.</p>
                <div id="status-message"></div>
                <textarea id="request-message" placeholder="Hi, it's..." maxlength="500" rows="4" style="width: 100%; max-width: 500px;"></textarea>
                <div style="margin-top: 10px;">
                    <span id="char-count">0/500</span>
                </div>
                <div id="control-tray" style="margin-top: 10px;">
                    <button id="btn-request-access">Request Access</button>
                    <button id="btn-copy-address">Copy Address</button>
                </div>
            </div>
            `

    // Character counter
    this.messageInput = this.container.querySelector('#request-message');
    this.charCount = this.container.querySelector('#char-count');
    this.messageInput.addEventListener('input', () => {
      this.charCount.textContent = `${this.messageInput.value.length}/500`;
    });

    // Copy address button
    this.copyAddress = this.container.querySelector('#btn-copy-address');
    this.copyAddress.addEventListener('click', () => {
      navigator.clipboard.writeText(window.epistery.wallet.address);
      this.showStatus('Address copied to clipboard', 'success');
    });

    // Request access button
    this.requestButton = this.container.querySelector('#btn-request-access');
    this.requestButton.addEventListener('click', async () => {
      await this.requestAccess();
    });
  }

  async requestAccess() {
    const message = this.messageInput.value.trim();
    const statusDiv = this.container.querySelector('#status-message');

    try {
      this.requestButton.disabled = true;
      this.requestButton.textContent = 'Submitting...';

      // Generate proof of wallet ownership (same pattern as epistery key exchange)
      const ethers = window.ethers;
      const wallet = window.epistery.wallet;

      if (!wallet || !ethers) {
        this.showStatus('Wallet not initialized. Please refresh the page.', 'error');
        this.requestButton.disabled = false;
        this.requestButton.textContent = 'Request Access';
        return;
      }

      // Create challenge and sign it to prove ownership
      const challenge = ethers.utils.hexlify(ethers.utils.randomBytes(32));
      const proofMessage = `Epistery Access Request - ${wallet.address} - ${challenge}`;
      const signature = await wallet.sign(proofMessage, ethers);

      const response = await fetch('/pending/access', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message,
          clientAddress: wallet.address,
          proofMessage,
          signature
        })
      });

      const data = await response.json();

      if (response.ok) {
        this.showStatus('Access request submitted successfully! The administrator will review your request.', 'success');
        this.messageInput.value = '';
        this.charCount.textContent = '0/500';
        this.requestButton.disabled = true;
        this.requestButton.textContent = 'Request Submitted';
      } else {
        this.showStatus(data.message || 'Failed to submit request', 'error');
        this.requestButton.disabled = false;
        this.requestButton.textContent = 'Request Access';
      }
    } catch (error) {
      console.error('Error submitting access request:', error);
      this.showStatus('An error occurred while submitting your request', 'error');
      this.requestButton.disabled = false;
      this.requestButton.textContent = 'Request Access';
    }
  }

  showStatus(message, type) {
    const statusDiv = this.container.querySelector('#status-message');
    statusDiv.textContent = message;
    statusDiv.style.padding = '10px';
    statusDiv.style.marginBottom = '10px';
    statusDiv.style.borderRadius = '4px';
    statusDiv.style.backgroundColor = type === 'success' ? '#d4edda' : '#f8d7da';
    statusDiv.style.color = type === 'success' ? '#155724' : '#721c24';
    statusDiv.style.border = `1px solid ${type === 'success' ? '#c3e6cb' : '#f5c6cb'}`;
  }
}
