import Component from "./Component.mjs";

export default class SignIn extends Component {
    constructor(props) {
        super(props);
    }
    async render(element) {
        await super.render(element);
        let form = this.div('login-form');
        form.innerHTML = `
            <div><input type='text' id='username' placeholder='username'/></div>
            <div><input type='password' id='password' placeholder='password'/></div>
            <div><select style="display:none" id='account'></select></div>
            <div><button id="submit">login</button></div>
            <div class="login-status"></div>
            `
        this.username = form.querySelector('#username');
        this.password = form.querySelector('#password');
        this.account = form.querySelector('#account');
        this.status = form.querySelector('.login-status');
        this.submit = form.querySelector('#submit');
        this.submit.addEventListener('click',this.onSubmit.bind(this));
    }
    async onSubmit(event) {
        this.status.innerHTML = "";
        let encoding = "Basic "+window.btoa(this.username.value+':'+this.password.value);
        let options = {credentials:'include',headers:{Authentication:encoding}}
        let url = '/session/login/'+this.account.value;
        let response = await fetch(url,options);
        if (response.ok) {
            let status = await response.json();
            if (status.accounts) {
                // account is ambiguous
                this.account.style.display='block';
                this.account.innerHTML = status.accounts.map(a=>`<option>${a}</option>`);
                this.status.innerHTML = "select account";
            } else {
                document.location.replace('/')
            }
        } else {
            this.status.innerHTML = "login failed";
        }
    }
}
