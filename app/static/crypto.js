// /static/crypto.js

const RSA_KEY_SIZE = 2048;
const PUBLIC_KEY_STORAGE_KEY = 'chat_public_key';
const PRIVATE_KEY_STORAGE_KEY = 'chat_private_key';

/**
 * Generates an RSA key pair and stores it in localStorage.
 */
async function generateAndStoreKeys() {
    const jsencrypt = new JSEncrypt({ default_key_size: RSA_KEY_SIZE });
    const privateKey = jsencrypt.getPrivateKey();
    const publicKey = jsencrypt.getPublicKey();

    localStorage.setItem(PUBLIC_KEY_STORAGE_KEY, publicKey);
    localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, privateKey);

    console.log("New key pair generated and stored.");
    return { publicKey, privateKey };
}

/**
 * Retrieves the stored key pair from localStorage.
 * If keys don't exist, it generates a new pair.
 */
async function getKeys() {
    let publicKey = localStorage.getItem(PUBLIC_KEY_STORAGE_KEY);
    let privateKey = localStorage.getItem(PRIVATE_KEY_STORAGE_KEY);

    if (!publicKey || !privateKey) {
        const newKeys = await generateAndStoreKeys();
        publicKey = newKeys.publicKey;
        privateKey = newKeys.privateKey;
    }

    return { publicKey, privateKey };
}

/**
 * Uploads the public key to the server.
 * @param {string} publicKey - The public key to upload.
 */
async function publishPublicKey(publicKey) {
    try {
        const response = await fetch('/keys/publish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ public_key: publicKey }),
        });
        if (response.ok) {
            console.log('Public key published successfully.');
        } else {
            console.error('Failed to publish public key.');
        }
    } catch (error) {
        console.error('Error publishing public key:', error);
    }
}

/**
 * Fetches a user's public key from the server.
 * @param {number} userId - The ID of the user.
 * @returns {Promise<string|null>} The public key or null if not found.
 */
async function fetchUserPublicKey(userId) {
    try {
        const response = await fetch(`/keys/user/${userId}`);
        if (response.ok) {
            const data = await response.json();
            return data.public_key;
        } else {
            console.error(`Failed to fetch public key for user ${userId}.`);
            return null;
        }
    } catch (error) {
        console.error(`Error fetching public key for user ${userId}:`, error);
        return null;
    }
}

/**
 * Encrypts a message using a public key.
 * @param {string} text - The plaintext message.
 * @param {string} publicKey - The recipient's public key.
 * @returns {string|false} The encrypted ciphertext or false on failure.
 */
function encryptMessage(text, publicKey) {
    const jsencrypt = new JSEncrypt();
    jsencrypt.setPublicKey(publicKey);
    return jsencrypt.encrypt(text);
}

/**
 * Decrypts a message using the user's private key.
 * @param {string} ciphertext - The encrypted message.
 * @returns {string|false} The decrypted plaintext or false on failure.
 */
function decryptMessage(ciphertext) {
    const privateKey = localStorage.getItem(PRIVATE_KEY_STORAGE_KEY);
    if (!privateKey) {
        console.error("Private key not found for decryption.");
        return false;
    }
    const jsencrypt = new JSEncrypt();
    jsencrypt.setPrivateKey(privateKey);
    return jsencrypt.decrypt(ciphertext);
}

/**
 * Initializes the crypto setup on the client-side.
 * Generates keys if they don't exist and publishes the public key.
 */
async function initializeCrypto() {
    const { publicKey } = await getKeys();
    await publishPublicKey(publicKey);
}
