function escapeHtml(input) {
    const htmlEntities = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    };
    return input.replace(/[&<>"']/g, match => htmlEntities[match]);
}

document.addEventListener('DOMContentLoaded', () => {
    const messageForm = document.getElementById('messageForm');
    if (messageForm) {
        messageForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(messageForm);
            fetch('/send_message', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Cообщение в список сообщений как outgoing
                    const messagesDiv = document.querySelector('.messages');
                    if (messagesDiv) {
                        const newMessageDiv = document.createElement('div');
                        newMessageDiv.classList.add('message', 'outgoing');

                        let username = escapeHtml(data.from_username);

                        let messageContent = '<div class="message-content">';
                        if (data.content) {
                            let content = escapeHtml(data.content);
                            messageContent += `<p>${content}</p>`;
                        }
                        if (data.file_path) {
                            let filepath = escapeHtml(data.file_path);
                            const fileUrl = `/uploads/${filepath}`;
                            if (/\.(jpg|jpeg|png|gif)$/i.test(filepath)) {
                                messageContent += `<img src="${fileUrl}" alt="Image" class="message-image">`;
                            } else {
                                messageContent += `<a href="${fileUrl}" target="_blank">Скачать файл</a>`;
                            }
                        }
                        newMessageDiv.innerHTML = messageContent + `<span class="timestamp">${data.timestamp} | ${username}</span></div>`;
                        messagesDiv.appendChild(newMessageDiv);
                        messagesDiv.scrollTop = messagesDiv.scrollHeight;
                        messageForm.reset();
                    }
                } else {
                    alert(data.error || 'Произошла ошибка');
                }
            })
            .catch(err => console.error(err));
        });
    }
});