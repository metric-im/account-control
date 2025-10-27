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
                <div id="control-tray" style="margin-top: 10px;">
                    <button id="btn-request-access">Continue</button>
                </div>
            </div>
            `
        // Request access button
        this.requestButton = this.container.querySelector('#btn-request-access');
        this.requestButton.addEventListener('click', async () => {
            await this.requestAccess();
        });
    }

    async requestAccess() {
        try {
            // Generate proof of wallet ownership (same pattern as epistery key exchange)
            const ethers = window.ethers;
            const wallet = window.epistery.wallet;

            // Create challenge and sign it to prove ownership
            const challenge = ethers.utils.hexlify(ethers.utils.randomBytes(32));
            const proofMessage = `Epistery Access Request - ${wallet.address} - ${challenge}`;
            const signature = await wallet.sign(proofMessage, ethers);

            const response = await fetch('/pending/access/automatic', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    clientAddress: wallet.address,
                    proofMessage,
                    signature
                })
            });

            const data = await response.json();

            if (response.ok) {
                window.location.reload();
            } else {
                window.toast.error('Something went wrong')
            }
        } catch (error) {
            window.toast.error(`Something went wrong: ${error}`)
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
