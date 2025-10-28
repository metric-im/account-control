import Component from "./Component.mjs";
import API from "./API.mjs";
import {InputSelect} from "./InputSelect.mjs";
import {InputText} from "./InputText.mjs";
import {Button} from "./Button.mjs";
import Witness from "/.well-known/epistery/lib/witness.js";

export default class Claim extends Component {
  constructor(props) {
    super(props);
    this.claimData = {
      provider: 'ethereum-mainnet',
      customName: '',
      customChainId: '',
      customRpc: ''
    };
    this.connectedWallet = null;
    this.challengeToken = null;
    this.currentStep = 1;

    // appName must be provided for user instruction to match generated DNS challenge
    this.appName = props.context?.domain?.appName || 'unknown';
  }

  async render(element) {
    await super.render(element);

    this.container = this.div('container',this.element);

    // Check for existing claim state on page load
    await this.restoreState();

    // Step 1: Chain Selection
    this.step1 = this.div('step-1',this.container);
    this.step1.innerHTML = `
      <h1>Welcome to ${location.hostname}</h1>
      <p>This is a private wiki that uses <a href="https://rootz.global">Rootz</a> data wallets for access and origin.
      If you own this domain, you can become admin of a wiki that can be shared with others you invite. We haven't
      yet figured out the business model, but it will involve data wallet credits for actions</p>
      <p>Data and administration are siloed by domain. This domain, ${location.hostname}, has not yet been claimed.
      Follow these steps to initialize </p>
      <p>Don't know why you are here? If you are not affiliated with this domain somehow, there's nothing for you to do.
      If you are curious, contact <a href="mailto:info@metric.im">info@metric.im</a></p>
      <h2>Step 1: Select Blockchain Network</h2>
      <p>Choose the blockchain network for this instance. Note that if you have a web3 plugin like metamask it
      will prompt you to select and connect an existing wallet. If not, the wallet be generated in your browser storage.
      You can back up this id or replace it with a more secure wallet id later if you like.</p>
    `;

    // Provider selection
    this.providerSelect = await this.draw(InputSelect, {
      title: "Blockchain Provider",
      name: "provider",
      data: this.claimData,
      options: [
        {name: "Ethereum Mainnet (Chain ID: 1)", value: "ethereum-mainnet"},
        {name: "Polkadot Asset Hub Testnet (Chain ID: 1000)", value: "polkadot-testnet"},
        {name: "Polygon Amoy Testnet (Chain ID: 80002)", value: "polygon-amoy"},
        {name: "Sepolia Testnet (Chain ID: 11155111)", value: "sepolia-testnet"},
        {name: "Custom Network", value: "custom"}
      ]
    },this.step1);

    // Custom network fields (initially hidden)
    this.customFields = this.div('custom-fields',this.step1);
    this.customFields.style.display = 'none';

    this.customNameInput = await this.draw(InputText, {
      title: "Network Name",
      name: "customName",
      data: this.claimData,
      placeholder: "e.g., My Custom Network"
    },this.customFields);

    this.customChainIdInput = await this.draw(InputText, {
      title: "Chain ID",
      name: "customChainId",
      data: this.claimData,
      placeholder: "e.g., 1337"
    },this.customFields);

    this.customRpcInput = await this.draw(InputText, {
      title: "RPC URL",
      name: "customRpc",
      data: this.claimData,
      placeholder: "e.g., https://my-rpc.example.com"
    },this.customFields);

    this.connectBtn = await this.draw(Button, {
      title: "Connect Wallet",
      onClick: this.connectWallet.bind(this)
    },this.step1);

    // Step 2: Wallet Info (initially hidden)
    this.step2 = this.div('step-2',this.container);
    this.step2.style.display = 'none';
    this.step2.innerHTML = `
      <h2>Step 2: Wallet Connected</h2>
      <p>Your wallet address: <span id="wallet-address"></span></p>
    `;

    this.generateBtn = await this.draw(Button, {
      title: "Generate DNS Challenge",
      onClick: this.generateChallenge.bind(this)
    },this.step2);

    // Step 3: DNS Challenge (initially hidden)
    this.step3 = this.div('step-3',this.container);
    this.step3.style.display = 'none';
    this.step3.innerHTML = `
      <h2>Step 3: DNS Verification</h2>
      <p>To establish <span id="address"></span> as the owner and admin, add a TXT record to your domain:</p>
      <table>
        <tr><th>Record Type</th><th>name</th><th>value</th></tr>
        <tr><td>TXT</td><td>_${this.appName}</td><td id="challenge-token"></td></tr>
      </table>
      <div id="control-tray">
      </div>
    `;

    // Setup provider selection change handler
    this.providerSelect.element.addEventListener('change', () => {
      this.toggleCustomFields();
    });

    // Listen for provider data updates from the InputSelect component
    this.providerSelect.element.addEventListener('input', () => {
      this.toggleCustomFields();
    });

    // Update UI based on restored state
    await this.updateStepDisplay();
  }

  async updateStepDisplay() {
    // Show appropriate step based on current state
    if (this.currentStep >= 2 && this.connectedWallet) {
      this.step2.querySelector('#wallet-address').textContent = this.connectedWallet;
      this.step2.style.display = 'block';
      this.connectBtn.element.textContent = 'Connected';
      this.connectBtn.element.style.background = '#28a745';
    }

    if (this.currentStep >= 3 && this.challengeToken) {
      this.step3.querySelector('#address').textContent = this.connectedWallet;
      this.step3.querySelector('#challenge-token').textContent = this.challengeToken;
      this.step3.style.display = 'block';

      // Add copy and verify buttons to control tray (clear first to avoid duplicates)
      const controlTray = this.step3.querySelector('#control-tray');
      controlTray.innerHTML = ''; // Clear existing buttons

      this.copyBtn = await this.draw(Button, {
        title: "Copy TXT Value",
        onClick: () => navigator.clipboard.writeText(this.challengeToken)
      },controlTray);

      this.verifyBtn = await this.draw(Button, {
        title: "Verify Domain",
        onClick: this.verifyDomain.bind(this)
      },controlTray);
    }
  }

  async restoreState() {
    try {
      // Check if there's an existing challenge token
      const existingChallenge = await API.get('/account/claim');
      if (existingChallenge && typeof existingChallenge === 'string') {
        this.challengeToken = existingChallenge;
        console.log('Restored existing challenge token');

        // Don't auto-connect - let user click "Connect Wallet" button
        // This avoids errors from unconfigured providers on page refresh
        this.currentStep = 1; // Show step 1 so user can connect wallet
      }
    } catch (error) {
      console.log('No existing claim state found, starting fresh');
      this.currentStep = 1;
    }
  }

  toggleCustomFields() {
    if (this.claimData.provider === 'custom') {
      this.customFields.style.display = 'block';
    } else {
      this.customFields.style.display = 'none';
    }
  }

  async connectWallet() {
    this.connectBtn.element.disabled = true;
    this.connectBtn.element.textContent = 'Connecting...';

    try {
      const providerConfig = this.getProviderConfig();
      console.log('Connecting with provider config:', providerConfig);

      // Validate custom network config if selected
      if (this.claimData.provider === 'custom') {
        if (!providerConfig.name || !providerConfig.chainId || !providerConfig.rpcUrl) {
          throw new Error('Please fill in all custom network fields');
        }
      }

      // Initialize Epistery domain with selected provider config
      try {
        const initResponse = await fetch('/.well-known/epistery/domain/initialize', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider: providerConfig })
        });

        if (!initResponse.ok) {
          const errorData = await initResponse.json();
          if (!errorData.error?.includes('already initialized')) {
            throw new Error(`Failed to initialize domain: ${errorData.error || 'Unknown error'}`);
          }
          // If already initialized, continue anyway
        }
      } catch (initError) {
        console.warn('Domain initialization warning:', initError);
        // Continue with connection attempt anyway
      }

      // Connect to the blockchain - skip key exchange for unclaimed domains
      // (wallet discovery only, server validation happens after DNS verification)
      window.epistery = await Witness.connect({ skipKeyExchange: true });

      // Verify connection was successful and we have a wallet address
      if (!window.epistery || !window.epistery.wallet || !window.epistery.wallet.address) {
        throw new Error('Connection successful but no wallet address available');
      }

      this.connectedWallet = window.epistery.wallet.address;
      console.log('Connected wallet:', this.connectedWallet);

      // Show step 2
      this.step2.querySelector('#wallet-address').textContent = this.connectedWallet;
      this.step2.style.display = 'block';
      this.currentStep = 2;

      // Update button to show success
      this.connectBtn.element.textContent = 'Connected';
      this.connectBtn.element.style.background = '#28a745';

    } catch (error) {
      console.error('Wallet connection failed:', error);

      // Show user-friendly error message
      let errorMessage = 'Failed to connect wallet';
      if (error.message.includes('User rejected')) {
        errorMessage = 'Wallet connection was cancelled';
      } else if (error.message.includes('No provider')) {
        errorMessage = 'No wallet found. Please install a Web3 wallet like MetaMask';
      } else if (error.message) {
        errorMessage = error.message;
      }

      alert(errorMessage);

      // Reset button
      this.connectBtn.element.disabled = false;
      this.connectBtn.element.textContent = 'Connect Wallet';
      this.connectBtn.element.style.background = '';
    }
  }

  getProviderConfig() {
    const configs = {
      'ethereum-mainnet': {
        name: 'Ethereum Mainnet',
        chainId: 1,
        rpcUrl: 'https://eth.llamarpc.com'
      },
      'polkadot-testnet': {
        name: 'Polkadot Asset Hub Testnet',
        chainId: 1000,
        rpcUrl: 'wss://polkadot-asset-hub-rpc.polkadot.io'
      },
      'polygon-amoy': {
        name: 'Polygon Amoy Testnet',
        chainId: 80002,
        rpcUrl: 'https://rpc-amoy.polygon.technology'
      },
      'sepolia-testnet': {
          name: 'Sepolia',
          chainId: 11155111,
          rpcUrl: 'https://eth-sepolia.g.alchemy.com/v2/NJPpVUeD8bVFjn_5fZcG3'
       },
      'custom': {
        name: this.claimData.customName,
        chainId: parseInt(this.claimData.customChainId),
        rpcUrl: this.claimData.customRpc
      }
    };

    return configs[this.claimData.provider];
  }

  async generateChallenge() {
    try {
      // Send provider config and wallet address along with the challenge request
      const providerConfig = this.getProviderConfig();
      const response = await fetch('/account/claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: providerConfig,
          clientAddress: this.connectedWallet
        })
      });

      if (!response.ok) {
        throw new Error('Failed to generate challenge');
      }

      this.challengeToken = await response.text();

      // Show step 3
      this.step3.querySelector('#address').textContent = this.connectedWallet;
      this.step3.querySelector('#challenge-token').textContent = this.challengeToken;
      this.step3.style.display = 'block';
      this.currentStep = 3;

      // Add copy and verify buttons to control tray (clear first to avoid duplicates)
      const controlTray = this.step3.querySelector('#control-tray');
      controlTray.innerHTML = ''; // Clear existing buttons

      this.copyBtn = await this.draw(Button, {
        title: "Copy TXT Value",
        onClick: () => navigator.clipboard.writeText(this.challengeToken)
      },controlTray);

      this.verifyBtn = await this.draw(Button, {
        title: "Verify Domain",
        onClick: this.verifyDomain.bind(this)
      },controlTray);

    } catch (error) {
      console.error('Challenge generation failed:', error);
      alert('Failed to generate challenge: ' + error.message);
    }
  }

  async verifyDomain() {
    try {
      // Ensure we have a connected wallet
      if (!this.connectedWallet) {
        alert('Please connect your wallet first');
        return;
      }

      // Pass the wallet address to verify it matches the challenge
      const result = await API.get(`/claim?address=${encodeURIComponent(this.connectedWallet)}`);
      if (result.status === 'success') {
        location.reload();
      } else {
        alert('Verification failed: ' + result.message);
      }
    } catch (error) {
      alert('Verification error: ' + error.message);
    }
  }
}
