import Component from "./Component.mjs";
import API from '../../../components/API.mjs';

export default class PendingRequests extends Component {
    constructor(props) {
        super(props);
        this.requests = [];
    }

    async render(element) {
        await super.render(element);

        this.requestsList = this.div('requests-list', this.container);
        try {
            this.requests = await API.get('/pending/access');
            this.displayRequests();
        } catch (error) {
            console.error('Error loading pending requests:', error);
        }
    }

    displayRequests() {
        if (this.requests.length === 0) {
            return;
        }

        for (let request of this.requests) {
            const requestCard = this.div('request-card', this.requestsList);

            const header = this.div('request-header', requestCard);
            const addressElem = document.createElement('div');
            addressElem.className = 'request-address';
            addressElem.textContent = request.address;
            header.appendChild(addressElem);

            const dateElem = document.createElement('div');
            dateElem.className = 'request-date';
            dateElem.textContent = new Date(request._created).toLocaleString();
            header.appendChild(dateElem);

            if (request.message) {
                const messageElem = this.div('request-message', requestCard);
                messageElem.textContent = request.message;
            }

            const actions = this.div('request-actions', requestCard);

            const acceptBtn = document.createElement('button');
            acceptBtn.className = 'btn-accept';
            acceptBtn.textContent = 'Accept';
            acceptBtn.addEventListener('click', async () => {
                await this.acceptRequest(request.address, acceptBtn);
            });
            actions.appendChild(acceptBtn);

            const rejectBtn = document.createElement('button');
            rejectBtn.className = 'btn-reject';
            rejectBtn.textContent = 'Reject';
            rejectBtn.addEventListener('click', async () => {
                await this.rejectRequest(request.address, rejectBtn);
            });
            actions.appendChild(rejectBtn);
        }
    }

    async acceptRequest(address, button) {
        try {
            button.disabled = true;
            button.textContent = 'Accepting...';

            await API.post(`/pending/access/${address}/accept`, {});

            // Remove from local list and refresh display
            this.requests = this.requests.filter(r => r.address !== address);
            this.displayRequests();

            window.toast.success('User created successfully');
        } catch (error) {
            console.error('Error accepting request:', error);
            button.disabled = false;
            button.textContent = 'Accept';
            window.toast.error(error.response || 'Failed to accept request');
        }
    }

    async rejectRequest(address, button) {
        try {
            button.disabled = true;
            button.textContent = 'Rejecting...';

            await API.post(`/pending/access/${address}/reject`, {});

            // Remove from local list and refresh display
            this.requests = this.requests.filter(r => r.address !== address);
            this.displayRequests();

            window.toast.success('Request rejected');
        } catch (error) {
            console.error('Error rejecting request:', error);
            button.disabled = false;
            button.textContent = 'Reject';
            window.toast.error(error.response || 'Failed to reject request');
        }
    }
}