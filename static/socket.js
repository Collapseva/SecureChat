document.addEventListener('DOMContentLoaded', () => {
    const socket = io();

    // Обработка новых приглашений
    socket.on('new_invitation', (data) => {
        const invitationsList = document.querySelector('.invitations-list');
        if (invitationsList) {
            const newInvitation = document.createElement('div');
            newInvitation.className = 'invitation-card';
            newInvitation.innerHTML = `
                <div class="invitation-header">
                    <div class="user-avatar">
                        <i class="fas fa-user-circle"></i>
                    </div>
                    <div class="invitation-details">
                        <h3>От ${data.from_username}</h3>
                        <span class="timestamp">Только что</span>
                    </div>
                </div>
                <div class="invitation-actions">
                    <form action="/invitation/accept/${data.invitation_id}" method="post">
                        <button type="submit" class="btn success"><i class="fas fa-check"></i>Принять</button>
                    </form>
                    <form action="/invitation/decline/${data.invitation_id}" method="post">
                        <button type="submit" class="btn danger"><i class="fas fa-times"></i>Отклонить</button>
                    </form>
                </div>`;
            invitationsList.prepend(newInvitation);
        }
    });

    // Обработка принятия приглашения
    socket.on('invitation_accepted', (data) => {
        const chatsList = document.querySelector('.chats-list');
        if (chatsList) {
            const newChat = document.createElement('li');
            newChat.innerHTML = `<a href="/chat/${data.chat_id}" class="chat-button">
                Чат с ${data.to_username}
            </a>`;
            chatsList.appendChild(newChat);
        }
    });

    // Обработка отклонения приглашения
    socket.on('invitation_declined', (data) => {
        alert(`${data.to_username} отклонил(а) ваше приглашение.`);
    });

    // Обработка новых сообщений (пришедших от других)
    socket.on('new_message', (data) => {
        if (window.location.pathname === `/chat/${data.chat_id}`) {
            const messagesDiv = document.querySelector('.messages');
            if (messagesDiv) {
                const newMessageDiv = document.createElement('div');
                newMessageDiv.classList.add('message', 'incoming');

                let messageContent = '';
                if (data.content) {
                    messageContent += `<p><strong>${data.from_username}:</strong> ${data.content}</p>`;
                }
                if (data.file_path) {
                    const fileUrl = `/uploads/${data.file_path}`;
                    if (/\.(jpg|jpeg|png|gif)$/i.test(data.file_path)) {
                        messageContent += `<p><strong>${data.from_username}:</strong></p>
                                           <img src="${fileUrl}" alt="Image" class="message-image">`;
                    } else {
                        messageContent += `<p><strong>${data.from_username}:</strong> <a href="${fileUrl}" target="_blank">Скачать файл</a></p>`;
                    }
                }
                newMessageDiv.innerHTML = messageContent + `<span class="timestamp">${data.timestamp}</span>`;
                messagesDiv.appendChild(newMessageDiv);
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
        } else {
            // Обновить счетчик непрочитанных
            const chatButton = document.querySelector(`a[href="/chat/${data.chat_id}"]`);
            if (chatButton) {
                let unreadCountSpan = chatButton.querySelector('.unread-count');
                if (unreadCountSpan) {
                    let count = parseInt(unreadCountSpan.textContent) + 1;
                    unreadCountSpan.textContent = count;
                } else {
                    unreadCountSpan = document.createElement('span');
                    unreadCountSpan.classList.add('unread-count');
                    unreadCountSpan.textContent = '1';
                    chatButton.appendChild(unreadCountSpan);
                }
            } else {
                const chatsList = document.querySelector('.chats-list');
                if (chatsList) {
                    const newChat = document.createElement('li');
                    newChat.innerHTML = `<a href="/chat/${data.chat_id}" class="chat-button">
                        Чат с ${data.from_username}
                        <span class="unread-count">1</span>
                    </a>`;
                    chatsList.appendChild(newChat);
                }
            }
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

    // Отправка собственного сообщения без перезагрузки
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
                        let messageContent = '';
                        if (data.content) {
                            messageContent += `<p><strong>${data.from_username}:</strong> ${data.content}</p>`;
                        }
                        if (data.file_path) {
                            const fileUrl = `/uploads/${data.file_path}`;
                            if (/\.(jpg|jpeg|png|gif)$/i.test(data.file_path)) {
                                messageContent += `<p><strong>${data.from_username}:</strong></p>
                                                   <img src="${fileUrl}" alt="Image" class="message-image">`;
                            } else {
                                messageContent += `<p><strong>${data.from_username}:</strong> <a href="${fileUrl}" target="_blank">Скачать файл</a></p>`;
                            }
                        }
                        newMessageDiv.innerHTML = messageContent + `<span class="timestamp">${data.timestamp}</span>`;
                        messagesDiv.appendChild(newMessageDiv);
                        messagesDiv.scrollTop = messagesDiv.scrollHeight;
                        // Очистим форму
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
