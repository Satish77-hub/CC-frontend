import React, { useState, useEffect } from 'react';
import { Amplify } from 'aws-amplify';
import {
  signIn,
  signOut,
  getCurrentUser,
  fetchAuthSession,
  signUp,
  confirmSignUp
} from 'aws-amplify/auth';
import { get, post } from 'aws-amplify/api';
import './App.css';


// --- DEPLOYMENT DETAILS (override with Vite env if set) ---
const API_URL = import.meta.env.VITE_API_URL || ' https://ye0jkh9k1d.execute-api.ap-south-1.amazonaws.com/Prod';
const USER_POOL_ID = import.meta.env.VITE_USER_POOL_ID || 'ap-south-1_QfOkTIS06';
const USER_POOL_CLIENT_ID = import.meta.env.VITE_USER_POOL_CLIENT_ID || '43id4o19emlj1mmvh3crhfcm9h';
const REGION = import.meta.env.VITE_AWS_REGION || 'ap-south-1';
// ------------------------------------------------


// --- CORRECT AMPLIFY V6 CONFIGURATION ---
Amplify.configure({
  Auth: {
    Cognito: {
      region: REGION,
      userPoolId: USER_POOL_ID,
      userPoolClientId: USER_POOL_CLIENT_ID,
      loginWith: {
        username: true,
        email: true,
        phone: false
      }
    },
  },
  API: {
    REST: {
      CCDedupAPI: {
        endpoint: API_URL,
        region: REGION, // <--- THIS IS THE FIX
        custom_header: async () => {
          try {
            const session = await fetchAuthSession();
            const token = session.tokens?.idToken?.toString();
            if (!token) throw new Error('No ID token found');
            return { Authorization: `Bearer ${token}` };
          } catch (e) {
            console.error('Error fetching auth session:', e);
            return {};
          }
        },
      },
    },
  },
});
// ------------------------------------------------
// ------------------------------------------------


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

  // Check for logged in user on page load
  useEffect(() => {
    (async () => {
      try {
        const currentUser = await getCurrentUser();
        setUser(currentUser);
        setView('dashboard');
      } catch {
        setUser(null);
        setView('login');
      }
    })();
  }, []);

  // Fetch dashboard data
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

  // --- Authentication ---
  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await signUp({ username: email, password });
      alert('Registration successful! Please check your email for a confirmation code.');
      setView('confirm');
    } catch (error) {
      alert(`Registration failed: ${error.message}`);
    }
  };

  const handleConfirm = async (e) => {
    e.preventDefault();
    try {
      await confirmSignUp({ username: email, confirmationCode: code });
      alert('Email confirmed! You can now log in.');
      setView('login');
    } catch (error) {
      alert(`Confirmation failed: ${error.message}`);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const cognitoUser = await signIn({ username: email, password });
      setUser(cognitoUser);
      setView('dashboard');
    } catch (error) {
      alert(`Login failed: ${error.message}`);
    }
  };

  const handleLogout = async () => {
    await signOut();
    setUser(null);
    setView('login');
    window.location.reload();
  };

  // --- File Management ---
  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      alert('Please select a file.');
      return;
    }

    try {
      const fileDataBase64 = await toBase64(selectedFile);
      await post({
        apiName: 'CCDedupAPI',
        path: '/upload',
        options: {
          body: {
            fileName: selectedFile.name,
            fileData: fileDataBase64
          },
        },
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
      const restOperation = get({
        apiName: 'CCDedupAPI',
        path: '/files',
      });
      const response = await restOperation.response;
      const filesData = await response.body.json();
      setFiles(filesData);
    } catch (error) {
      console.error('Error fetching files:', error);
      setFiles([]);
    }
  };

  const downloadFile = async (fileId) => {
    try {
      const restOperation = get({
        apiName: 'CCDedupAPI',
        path: `/download/${fileId}`,
      });
      const response = await restOperation.response;
      const res = await response.body.json();
      window.open(res.downloadUrl, '_blank');
    } catch (error) {
      console.error('Error downloading file:', error);
      alert('Could not get download link.');
    }
  };

  const fetchAdminMetrics = async () => {
    try {
      const session = await fetchAuthSession();
      const groups = session.tokens?.idToken?.payload['cognito:groups'];
      if (groups && groups.includes('Admins')) {
        setIsAdmin(true);
        const restOperation = get({
          apiName: 'CCDedupAPI',
          path: '/admin/metrics',
        });
        const response = await restOperation.response;
        const metricsData = await response.body.json();
        setMetrics(metricsData);
      } else setIsAdmin(false);
    } catch (error) {
      console.error('Could not fetch admin metrics:', error);
      setIsAdmin(false);
    }
  };

  // --- Render Views ---
  const renderAuth = () => (
    <div id="auth-container">
      {view === 'login' && (
        <div>
          <h1>Login</h1>
          <form onSubmit={handleLogin}>
            <input type="email" placeholder="Email" required onChange={(e) => setEmail(e.target.value)} />
            <input type="password" placeholder="Password" required onChange={(e) => setPassword(e.target.value)} />
            <button type="submit">Login</button>
            <p>New user? <a onClick={() => setView('register')}>Register here</a></p>
          </form>
        </div>
      )}
      {view === 'register' && (
        <div>
          <h1>Register</h1>
          <form onSubmit={handleRegister}>
            <input type="email" placeholder="Email" required onChange={(e) => setEmail(e.target.value)} />
            <input type="password" placeholder="Password" required onChange={(e) => setPassword(e.target.value)} />
            <button type="submit">Register</button>
            <p>Already have an account? <a onClick={() => setView('login')}>Login here</a></p>
          </form>
        </div>
      )}
      {view === 'confirm' && (
        <div>
          <h2>Confirm Email</h2>
          <form onSubmit={handleConfirm}>
            <input type="text" placeholder="Confirmation Code" required onChange={(e) => setCode(e.target.value)} />
            <button type="submit">Confirm</button>
          </form>
        </div>
      )}
    </div>
  );

  const renderDashboard = () => (
    <div id="dashboard">
      <button onClick={handleLogout}>Logout</button>
      <h1>Upload File</h1>
      <form onSubmit={handleUpload}>
        <input type="file" id="file-input" required onChange={(e) => setSelectedFile(e.target.files[0])} />
        <button type="submit">Upload</button>
      </form>

      <h2>My Files</h2>
      <ul>
        {files.length === 0 ? (
          <li>No files uploaded yet.</li>
        ) : (
          files.map((file) => (
            <li key={file.fileId}>
              <span>{file.fileName} (v{file.version})</span>
              <button onClick={() => downloadFile(file.fileId)}>Download</button>
            </li>
          ))
        )}
      </ul>

      {isAdmin && metrics && (
        <div>
          <h2>Admin Dashboard</h2>
          <p>Total Files: {metrics.summary.totalFiles}</p>
          <p>Total Original Size: {metrics.summary.totalOriginalMB} MB</p>
          <p>Stored (Deduplicated): {metrics.summary.totalStoredMB} MB</p>
          <p>Space Saved: {metrics.summary.savedMB} MB</p>
        </div>
      )}
    </div>
  );

  return <div>{view === 'dashboard' ? renderDashboard() : renderAuth()}</div>;
}

export default App;
