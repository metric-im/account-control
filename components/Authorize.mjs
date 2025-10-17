import Component from "./Component.mjs";
import Witness from "/.well-known/epistery/lib/witness.js";
import PageBody from './PageBody.mjs';
import Register from './Register.mjs';
import API from './API.mjs';

export default class Authorize extends Component {
  constructor(props) {
    super(props);
  }

  async render(element) {
    await super.render(element);
    this.pageMain = document.querySelector('.page-main');

    // Check if we already have a valid session
    this.context = Object.assign(this.props.context, this.props.sessionContext);

    if (!this.context.id && !window.epistery) {
      // No valid session, show connection UI and perform key exchange
      this.container = this.div('container');
      this.container.innerHTML = `
        <h1>Welcome to ${location.hostname}</h1>
        <p>This is a private wiki that uses <a href="https://rootz.global">Rootz</a> data wallets for access and origin.
        <p>If you have a web3 wallet plugin, it will launch and ask for a compatible wallet to get you to this site. This
        is for authentication. Please proceed only if you intend to interact with this site. Requesting address...</p>
        <a href="https://epistery.com/">Learn more at epistery.com</a>
      `;

      try {
        window.epistery = await Witness.connect();
        const contextUpdate = await API.get('/session/context');
        Object.assign(this.context, contextUpdate);
      } catch (error) {
        console.error('Failed to connect to blockchain:', error);
        // Show error but don't reload - this prevents infinite loops for users without web3
        this.showConnectionError(element);
        return;
      }
    }

    // Valid session exists, proceed to main app
    this.fire('contextUpdate', this.context);

    this.pageMain.innerHTML = '';
    if (this.context.id) {
      // User is authenticated and registered - show main app
      this.body = await this.draw(PageBody,{context:this.context},this.pageMain);
    } else {
      // User is connected but not registered - show register page
      this.body = await this.draw(Register,{context:this.context},this.pageMain);
    }
  }
  showConnectionError(element) {
    let pageMain = this.div('page-main');
    pageMain.innerHTML = `
      <div class="container">
          <h1>Connection Error</h1>
          <p>Failed to connect to the blockchain network. If you use a Web3 agent, please make sure it is running.</p>
          <button onclick="location.reload()">Retry</button>
      </div>
    `;
  }
  update(context) {
    this.body.update(context);
  }
}
