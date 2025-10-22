import React, { useState, useEffect } from 'react';
import { Amplify } from 'aws-amplify';
import {
    signIn,
    signOut,
    getCurrentUser,
    fetchAuthSession,
    signUp,          // <-- Added
    confirmSignUp    // <-- Added
} from 'aws-amplify/auth';
import { get, post } from 'aws-amplify/api';
import './App.css';

// --- YOUR DEPLOYMENT DETAILS ---
const API_URL = 'https://7f80ndql3i.execute-api.ap-south-1.amazonaws.com/Prod';
const USER_POOL_ID = 'ap-south-1_T34nXOQMw';
const USER_POOL_CLIENT_ID = '1b595rsph4m2op4at0gadvnjqv';
// ------------------------------------------

// --- V6 AMPLIFY CONFIGURATION ---
Amplify.configure({
    Auth: {
        Cognito: { // <--- v6 Change
            userPoolId: USER_POOL_ID,
            userPoolWebClientId: USER_POOL_CLIENT_ID,
        }
    },
    API: {
        REST: { // <--- v6 Change
            "CCDedupAPI": { // <--- v6 Change (API name is the key)
                endpoint: API_URL,
                custom_header: async () => {
                    try {
                        // v6 method to get token
                        const session = await fetchAuthSession();
                        const token = session.tokens?.idToken?.toString();
                        if (!token) { throw new Error("No ID token found"); }
                        return { Authorization: `Bearer ${token}` }
                    } catch (e) {
                        console.error("Error fetching auth session:", e);
                        return {}
                    }
                }
            }
        }
    }
});
// ----------------------------------

function App() {
    const [user, setUser] = useState(null);
    const [view, setView] = useState('login'); // login, register, confirm, dashboard
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [code, setCode] = useState('');
    const [files, setFiles] = useState([]);
    const [metrics, setMetrics] = useState(null);
    const [isAdmin, setIsAdmin] = useState(false);
    const [selectedFile, setSelectedFile] = useState(null);

    // Check for logged-in user on page load
    useEffect(() => {
        (async () => {
            try {
                // v6: Use imported function
                const currentUser = await getCurrentUser();
                setUser(currentUser);
                setView('dashboard');
            } catch (e) {
                setUser(null);
                setView('login');
            }
        })();
    }, []);

    // Fetch data when dashboard is shown
    useEffect(() => {
        if (view === 'dashboard') {
            fetchFiles();
            fetchAdminMetrics();
        }
    }, [view]);

    const toBase64 = (file) => new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.onerror = reject;
    });

    // --- Auth Handlers (v6) ---
    const handleRegister = async (e) => {
        e.preventDefault();
        try {
            // v6: Use imported function with object
            await signUp({ username: email, password });
            alert('Registration successful! Please check your email for a confirmation code.');
            setView('confirm');
        } catch (error) { alert(`Registration failed: ${error.message}`); }
    };

    const handleConfirm = async (e) => {
        e.preventDefault();
        try {
            // v6: Use imported function with object
            await confirmSignUp({ username: email, confirmationCode: code });
            alert('Email confirmed! You can now log in.');
            setView('login');
        } catch (error) { alert(`Confirmation failed: ${error.message}`); }
    };

    const handleLogin = async (e) => {
        e.preventDefault();
        try {
            // v6: Use imported function with object
            const cognitoUser = await signIn({ username: email, password });
            setUser(cognitoUser);
            setView('dashboard');
        } catch (error) { alert(`Login failed: ${error.message}`); }
    };

    const handleLogout = async () => {
        // v6: Use imported function
        await signOut();
        setUser(null);
        setView('login');
        window.location.reload(); // Reload to clear all state
    };

    // --- App Handlers (v6) ---
    const handleUpload = async (e) => {
        e.preventDefault();
        if (!selectedFile) { alert('Please select a file.'); return; }
        try {
            const fileDataBase64 = await toBase64(selectedFile);
            
            // v6: Use imported function with object
            await post({
                apiName: 'CCDedupAPI',
                path: '/upload',
                options: {
                    body: {
                        fileName: selectedFile.name,
                        fileData: fileDataBase64
                    }
                }
            });

            alert('File uploaded successfully!');
            fetchFiles();
            document.getElementById('file-input').value = null;
            setSelectedFile(null);
        } catch (error) {
            console.error('Upload Error:', error);
            alert(`Upload failed: ${error.message || JSON.stringify(error)}`);
        }
    };

    const fetchFiles = async () => {
        try {
            // v6: Use imported function and await response
            const restOperation = get({
                apiName: 'CCDedupAPI',
                path: '/files'
            });
            const response = await restOperation.response;
            const filesData = await response.body.json(); // <-- v6 requires parsing
            
            setFiles(filesData);
        } catch (error) {
            console.error('Error fetching files:', error);
            setFiles([]);
        }
    };

    const downloadFile = async (fileId) => {
        try {
            // v6: Use imported function and await response
            const restOperation = get({
                apiName: 'CCDedupAPI',
                path: `/download/${fileId}`
            });
            const response = await restOperation.response;
            const res = await response.body.json(); // <-- v6 requires parsing

            window.open(res.downloadUrl, '_blank');
        } catch (error) {
            console.error('Error downloading file:', error);
            alert('Could not get download link.');
        }
    };

    const fetchAdminMetrics = async () => {
        try {
            // v6: Use imported function
            const session = await fetchAuthSession();
            // v6: Get payload from tokens object
            const groups = session.tokens?.idToken?.payload['cognito:groups'];
            
            if (groups && groups.includes('Admins')) {
                setIsAdmin(true);

                // v6: Use imported function and await response
                const restOperation = get({
                    apiName: 'CCDedupAPI',
                    path: '/admin/metrics'
                });
                const response = await restOperation.response;
                const metricsData = await response.body.json(); // <-- v6 requires parsing
                
                setMetrics(metricsData);
            } else {
                setIsAdmin(false);
            }
        } catch (error) {
            console.error('Could not fetch admin metrics:', error);
            setIsAdmin(false);
        }
    };

    // --- Render Logic (No changes needed) ---
    const renderAuth = () => (
        <div id="auth-container">
            {view === 'login' && (
                <div id="loginView">
                    <h1>Login</h1>
                    <form id="loginForm" onSubmit={handleLogin}>
                        <input type="email" id="login-email" placeholder="Email" required onChange={e => setEmail(e.target.value)} />
                        <input type="password" id="login-password" placeholder="Password" required onChange={e => setPassword(e.target.value)} />
                        <button type="submit">Login</button>
                        <p>New user? <a onClick={() => setView('register')}>Register here</a></p>
                    </form>
                </div>
            )}
            {view === 'register' && (
                <div id="registerView">
                    <h1>Register</h1>
                    <form id="registerForm" onSubmit={handleRegister}>
                        <input type="email" id="reg-email" placeholder="Email" required onChange={e => setEmail(e.target.value)} />
                        <input type="password" id="reg-password" placeholder="Password" required onChange={e => setPassword(e.target.value)} />
                        <button type="submit">Register</button>
                        <p>Already have an account? <a onClick={() => setView('login')}>Login here</a></p>
                    </form>
                </div>
            )}
            {view === 'confirm' && (
                 <div id="confirmForm">
                    <h2>Confirm Email</h2>
                    <form onSubmit={handleConfirm}>
                        <input type="text" id="confirmation-code" placeholder="Confirmation Code" required onChange={e => setCode(e.target.value)} />
                        <button id="confirmBtn" type="submit">Confirm</button>
                    </form>
                </div>
            )}
        </div>
    );

    const renderDashboard = () => (
        <div id="dashboard">
            <button id="logoutBtn" onClick={handleLogout}>Logout</button>
            <h1>Upload File</h1>
            <form id="uploadForm" onSubmit={handleUpload}>
                <input type="file" id="file-input" required onChange={e => setSelectedFile(e.target.files[0])} />
                <button type="submit">Upload</button>
            </form>
            
            <h2>My Files</h2>
            <ul id="fileList">
                {files.length === 0 ? (
                    <li>No files uploaded yet.</li>
                ) : (
                    files.map(file => (
                        <li key={file.fileId}>
                            <span>{file.fileName} (v{file.version})</span>
                            <div><button onClick={() => downloadFile(file.fileId)}>Download</button></div>
                        </li>
                    ))
                )}
            </ul>
            
            {isAdmin && metrics && (
                <div id="admin-section">
                    <h2>Admin Dashboard</h2>
                    <div id="metrics-summary">
                        <p><strong>Total Files:</strong> {metrics.summary.totalFiles}</p>
                        <p><strong>Total Original Size:</strong> {metrics.summary.totalOriginalMB} MB</p>
                        <p><strong>Stored (Deduplicated):</strong> {metrics.summary.totalStoredMB} MB</p>
                        <p><strong>Space Saved:</strong> {metrics.summary.savedMB} MB</p>
                    </div>
                    <h3>User Storage Overview</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>User Email</th>
                                <th>File Count</th>
                                <th>Storage Used (Original)</th>
                                <th>Status</th>
                                <th>Joined</th>
                            </tr>
                        </thead>
                        <tbody id="user-table-body">
                            {metrics.users.length === 0 ? (
                                <tr><td colSpan="5">No users found.</td></tr>
                            ) : (
                                metrics.users.map(user => (
                                    <tr key={user.userId}>
                                        <td>{user.email || user.userId}</td>
                                        <td>{user.fileCount || '0'}</td>
                                        <td>{user.totalOriginalSizeMB} MB</td>
                                        <td>{user.status || 'N/A'}</td>
                                        <td>{user.createdDate ? new Date(user.createdDate).toLocaleDateString() : 'N/A'}</td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );

    return (
        <div>
            {view === 'dashboard' ? renderDashboard() : renderAuth()}
        </div>
    );
}

export default App;