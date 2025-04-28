document.getElementById('logout-btn').addEventListener('click', function() {
    window.location.href = '/logout';
});

const url = new URL(window.location.href);
const serviceName = url.searchParams.get('name');

const socket = io.connect('http://' + document.domain + ':' + location.port);
socket.on('new_stream', (newStream) => {
    if (serviceName === newStream.service || serviceName === null) {
        const streamList = document.querySelector('.stream-list');
        const newStreamElement = document.createElement('a');
        newStreamElement.href = `/streams/${newStream.id}`;
        newStreamElement.className = 'stream-item';
        newStreamElement.target = '_blank';
        newStreamElement.rel = 'noopener noreferrer';

        newStreamElement.innerHTML = `
            <span>Stream ${newStream.id}</span>
            <div class="flags-container">
                ${newStream.flags.map(flag => `<div class="flag-text">${flag}</div>`).join('')}
            </div>
        `;

        streamList.prepend(newStreamElement);
    }
});