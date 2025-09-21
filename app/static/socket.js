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
    const socket = io.connect('http://' + document.domain + ':' + location.port);

    // Обработка новых приглашений
    socket.on('new_invitation', (data) => {
        const invitationsSection = document.querySelector('.invitations-section.card')
        let invitationsList = document.querySelector('.invitations-list');
        let exmptyState = document.querySelector('.invitations-section.card .empty-state');
        if (exmptyState)
            exmptyState.remove()
        if (!invitationsList) {
            if (invitationsSection)
            {
                invitationsList = document.createElement('div');
                invitationsList.className = 'invitation-list';
                invitationsSection.append(invitationsList);
            }
        }
        if (invitationsList) {
            const newInvitation = document.createElement('div');
            let username = escapeHtml(data.from_username);
            let chat_name = escapeHtml(data.chat_name);
            newInvitation.className = 'invitation-card';
            newInvitation.innerHTML = `
                    <div class="invitation-header">
                        <div class="user-avatar">
                            <i class="fas fa-user-circle"></i>
                        </div>
                        <div class="invitation-details">
                            <h3>От ${username}</h3>
                            <span class="timestamp">
                                ${data.timestamp}
                            </span>
                            <span class="chat-info">
                                <i class="fas fa-comments"></i>
                                ${chat_name}
                            </span>
                        </div>
                    </div>
                    <div class="invitation-actions">
                        <form action="/invitation/accept/${data.invitation_id}" method="post">
                            <button type="submit" class="btn success">
                                <i class="fas fa-check"></i> Принять
                            </button>
                        </form>
                        <form action="/invitation/decline/${data.invitation_id}" method="post">
                            <button type="submit" class="btn danger">
                                <i class="fas fa-times"></i> Отклонить
                            </button>
                        </form>
                    </div>`;
            invitationsList.prepend(newInvitation);
        }
    });

    // Обработка отклонения приглашения
    socket.on('invitation_declined', (data) => {
        //alert(`${data.to_username} отклонил(а) ваше приглашение.`);
    });

    // Обработка новых сообщений (пришедших от других)
    socket.on('new_message', (data) => {
        if (window.location.pathname === `/chat/${data.chat_id}`) {
            const messagesDiv = document.querySelector('.messages');
            if (messagesDiv) {
                const newMessageDiv = document.createElement('div');
                newMessageDiv.classList.add('message', 'incoming');

                let username = escapeHtml(data.from_username);
                let messageText = data.content;

                // Decrypt message if it's not a group chat
                if (typeof otherUserId !== 'undefined' && otherUserId) {
                    const decryptedText = decryptMessage(data.content);
                    if (decryptedText) {
                        messageText = decryptedText;
                    } else {
                        messageText = "[Не удалось расшифровать сообщение]";
                    }
                }

                let messageContent = '<div class="message-content">';
                if (data.content) {
                    let content = escapeHtml(messageText);
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
            }
        } else {
            const chatItem = document.querySelector(`a[href="/chat/${data.chat_id}"]`);
            if (chatItem) {
                const unreadSpan = chatItem.querySelector('.unread-badge') || 
                    document.createElement('span');
                if (!chatItem.querySelector('.unread-badge')) {
                    unreadSpan.className = 'unread-badge';
                    chatItem.appendChild(unreadSpan);
                }
                unreadSpan.textContent = parseInt(unreadSpan.textContent || 0) + 1;
            }

        }
    });
});
