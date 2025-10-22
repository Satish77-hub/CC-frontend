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
// Removed unused 'get' and 'post' from 'aws-amplify/api' - using fetch directly
import './App.css';

// --- DEPLOYMENT DETAILS (Update with your actual values after SAM deploy) ---
const API_URL = import.meta.env.VITE_API_URL || 'https://gvdll7gwm8.execute-api.ap-south-1.amazonaws.com/Prod'; // Replace! Crucial!
const USER_POOL_ID = import.meta.env.VITE_USER_POOL_ID || ' ap-south-1_oDVjcVYmv'; // Replace! Crucial!
const USER_POOL_CLIENT_ID = import.meta.env.VITE_USER_POOL_CLIENT_ID || '25euuao1vcennktrugit4vsg50'; // Replace! Crucial!
const REGION = import.meta.env.VITE_AWS_REGION || 'ap-south-1'; // Ensure this matches your deployment region
// -----------------------------------------------------------

// --- Amplify Config (Mainly for Auth) ---
Amplify.configure({
  Auth: {
    Cognito: {
      region: REGION,
      userPoolId: USER_POOL_ID,
      userPoolClientId: USER_POOL_CLIENT_ID,
      // loginWith: // Not needed for USER_PASSWORD_AUTH flow used by Amplify default UI/functions
    },
  },
  // API category config helps Amplify know the region for signing requests if needed,
  // but we primarily use fetch with manual token attachment.
  API: {
    REST: {
      MiniDriveAPI: { // An arbitrary name for this config block
        endpoint: API_URL,
        region: REGION,
      },
    },
  },
});
// ----------------------------------------

const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB chunks

// Calculate SHA-256 hash of an ArrayBuffer
async function calculateHash(arrayBuffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper to get Auth token for fetch requests
async function getAuthToken() {
    try {
        // Use forceRefresh: true if you encounter token expiry issues during long operations
        const session = await fetchAuthSession({ forceRefresh: false });
        return session.tokens?.idToken?.toString();
    } catch (err) {
        // console.warn("Could not get auth session. User might be logged out.", err);
        return null; // Return null if session is invalid or user is logged out
    }
}

// Helper to construct public share URL based on API Gateway base URL
function getPublicShareUrl(shareId) {
    if (!shareId || !API_URL || API_URL.includes('PASTE_YOUR')) return ''; // Avoid constructing invalid URL
    // Assumes API_URL is the base path (e.g., https://<id>.execute-api.<region>.amazonaws.com/Prod)
    // Ensure API_URL doesn't have a trailing slash if path starts with one
    const baseUrl = API_URL.endsWith('/') ? API_URL.slice(0, -1) : API_URL;
    return `${baseUrl}/public-download/${shareId}`;
}


function App() {
  const [user, setUser] = useState(null); // Stores { username, userId } from Cognito
  const [isAdmin, setIsAdmin] = useState(false);
  const [view, setView] = useState('login'); // 'login', 'register', 'confirm', 'dashboard'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [files, setFiles] = useState([]); // Array of file metadata objects
  const [metrics, setMetrics] = useState(null); // Admin metrics object
  const [uploadProgress, setUploadProgress] = useState(null); // { status: string, percent: number, message?: string } | null
  const [downloadProgress, setDownloadProgress] = useState(null); // { status: string, percent: number, message?: string } | null
  const [shareLinkInfo, setShareLinkInfo] = useState({ fileId: null, link: '', error: '' }); // State for sharing modal/display
  const [isLoadingAuth, setIsLoadingAuth] = useState(true); // Prevent brief flash of login screen

  // --- Effects ---
  // Check login status only once on initial load
  useEffect(() => {
    checkCurrentUser();
  }, []);

  // Fetch data when user logs in or view changes to dashboard
  useEffect(() => {
    // Only fetch if logged in and on the dashboard
    if (user && view === 'dashboard') {
      fetchFiles(); // Fetch user's files
      if (isAdmin) {
          fetchAdminMetrics(); // Fetch admin data if user is admin
      } else {
          setMetrics(null); // Clear metrics if user is not admin or logs out
      }
    } else {
        // Clear data if logged out or not on dashboard
        setFiles([]);
        setMetrics(null);
    }
  }, [user, view, isAdmin]); // Dependencies that trigger re-fetch


  // --- Auth Functions ---
  async function checkCurrentUser() {
      setIsLoadingAuth(true); // Start loading indicator
      try {
        // Get user attributes AND session in parallel for efficiency
        const [currentUserData, session] = await Promise.all([
             getCurrentUser(), // Gets attributes like sub (userId), username
             fetchAuthSession({ forceRefresh: false }) // Gets tokens, including ID token with groups
        ]);
        const groups = session.tokens?.idToken?.payload['cognito:groups'];
        const userIsAdmin = Array.isArray(groups) && groups.includes('Admins');

        // Store essential user info, Cognito 'sub' is the unique userId
        setUser({ username: currentUserData.username, userId: currentUserData.userId });
        setIsAdmin(userIsAdmin);
        setView('dashboard'); // Go to dashboard if successful
      } catch (err) {
        // console.log("checkCurrentUser error:", err); // Log error for debugging
        setUser(null);
        setIsAdmin(false);
        setView('login'); // Go to login if not authenticated
      } finally {
          setIsLoadingAuth(false); // Stop loading indicator
      }
  }

  const handleRegister = async (e) => {
    e.preventDefault();
    // Use standard fetch to hit our /register endpoint, NOT Amplify's signUp
    try {
       if (!API_URL || API_URL.includes('PASTE_YOUR')) throw new Error("API URL not configured.");
       const response = await fetch(`${API_URL}/register`, {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ email, password })
       });
       const data = await response.json();
       if (!response.ok) throw new Error(data.message || 'Registration failed');

      alert('Registration successful! Please check your email for a confirmation code.');
      setView('confirm'); // Move to confirmation screen

    } catch (error) {
      console.error("Registration Frontend Error:", error);
      alert(`Registration failed: ${error.message}`);
    }
  };

  // Uses Amplify's confirmSignUp to interact directly with Cognito
  const handleConfirm = async (e) => {
    e.preventDefault();
    try {
      if (!USER_POOL_ID || USER_POOL_ID.includes('PASTE_YOUR')) throw new Error("Cognito User Pool not configured.");
      await confirmSignUp({ username: email, confirmationCode: code });
      alert('Email confirmed successfully! You can now log in.');
      // Reset fields and go to login
      // Don't clear email automatically, user might need it if confirm fails/retries
      // setEmail('');
      setPassword(''); // Clear password field
      setCode('');
      setView('login');
    } catch (error) {
      alert(`Confirmation failed: ${error.message}`);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      if (!USER_POOL_ID || USER_POOL_ID.includes('PASTE_YOUR')) throw new Error("Cognito User Pool not configured.");
      // Use Amplify's signIn which handles SRP flow
      const { isSignedIn } = await signIn({ username: email, password });
      if (isSignedIn) {
          // Re-check user details (sub, username) and groups after sign in
          await checkCurrentUser();
          // No need to setView here, checkCurrentUser does it
      } else {
          // This state implies MFA setup or other challenges not handled in this basic setup
          alert('Sign in needs further steps (e.g., MFA not supported in this demo).');
      }
    } catch (error) {
        // Clear user state on failure
        setUser(null);
        setIsAdmin(false);
        console.error("Login Frontend Error:", error);
        alert(`Login failed: ${error.message}`); // Provide Cognito error message
    }
  };

  const handleLogout = async () => {
      try {
        await signOut({ global: true }); // Sign out from all devices if desired
      } catch (error) {
          console.error("Sign out error:", error);
          // Proceed with clearing local state even if global sign out fails
      } finally {
          // Always clear local state and redirect
          setUser(null);
          setIsAdmin(false);
          setFiles([]);
          setMetrics(null);
          setEmail(''); // Clear sensitive form fields on logout
          setPassword('');
          setCode('');
          // Clear any potentially sensitive state variables
          localStorage.clear(); // Example: Clear everything if using localStorage (Amplify manages its own)
          setView('login');
          // No window.location.reload() needed if state updates correctly trigger re-render
      }
  };

  // --- API Call Helper ---
  async function makeApiCall(path, method = 'GET', body = null) {
      if (!API_URL || API_URL.includes('PASTE_YOUR')) {
         throw new Error("API URL is not configured. Please update App.jsx.");
      }

      const token = await getAuthToken(); // Fetches ID Token
      const isPublicPath = path.startsWith('/public-download'); // Allow public download path without token

      // If no token and it's a protected path, throw error or trigger logout
      if (!token && !['/register', '/login'].includes(path) && !isPublicPath) {
          console.error("Attempted protected API call without token:", path);
          handleLogout(); // Force logout if token is missing when expected
          throw new Error('Authentication token is missing or expired. Please log in again.');
      }

      const headers = { 'Content-Type': 'application/json' };
      // Only include Authorization header for protected routes
      if (token && !isPublicPath) {
          headers['Authorization'] = token; // Use the ID token directly
      }

      const options = { method, headers };
      if (body) options.body = JSON.stringify(body);

      // Construct full URL, ensure no double slashes if path starts with /
      const baseUrl = API_URL.replace(/\/$/, ''); // Remove trailing slash if present
      const fullUrl = `${baseUrl}${path.startsWith('/') ? '' : '/'}${path}`;


      const response = await fetch(fullUrl, options);

      // Try parsing JSON, but handle cases where response might be empty (e.g., 204 No Content)
      let data = {}; // Default to empty object
      const contentType = response.headers.get("content-type");
      try {
          // Only attempt to parse JSON if the content type indicates it and status is not 204
          if (contentType && contentType.indexOf("application/json") !== -1 && response.status !== 204) {
             data = await response.json();
          } else if (!response.ok) {
              // If not JSON and not ok, try to read as text for error message
              data.message = await response.text();
          }
      } catch (e) {
         // Handle cases where response is not JSON
         console.error("Failed to parse JSON response:", e);
         // Throw a generic error or handle based on status code
         if (!response.ok) throw new Error(`Request failed with status ${response.status} and non-JSON response.`);
         // If response was ok but not JSON (unlikely for this API), return empty object
      }


      if (!response.ok) {
          console.error("API Error Response:", { status: response.status, path, data });
          // Create an error object that includes the status and potentially a message from JSON or text
          const error = new Error(data?.message || `Request failed with status ${response.status}`);
          error.status = response.status;
          throw error;
      }
      return data; // Return parsed JSON data or empty object
  }


  // --- Data Fetching ---
  const fetchFiles = async () => {
    try {
      const filesData = await makeApiCall('/files');
      // Sort files by upload date, newest first
      setFiles(filesData.sort((a, b) => new Date(b.uploadDate) - new Date(a.uploadDate)));
    } catch (error) {
      console.error('Error fetching files:', error);
      setFiles([]); // Clear files on error
      if (error.message.includes('Authentication token')) {
          // Token issue likely handled by makeApiCall forcing logout
      } else {
          alert(`Failed to load your files: ${error.message}`);
      }
    }
  };

   const fetchAdminMetrics = async () => {
      setMetrics(null); // Show loading state
      try {
        const metricsData = await makeApiCall('/admin/metrics');
        setMetrics(metricsData); // Set the received metrics object
      } catch (error) {
        console.error('Could not fetch admin metrics:', error);
        if (error.status === 403) {
            // If backend explicitly says Forbidden, update admin status
            console.warn("User lacks admin privileges according to backend.");
            setIsAdmin(false); // Correct local state if backend check fails
        } else {
            // Show alert for other errors
            alert(`Failed to load admin metrics: ${error.message}`);
        }
        setMetrics(null); // Clear metrics on any error
      }
  };


  // --- File Operations ---
  const handleUpload = async (e) => {
    e.preventDefault();
    const fileInput = e.target.file; // Get the input element by name="file"
    const file = fileInput?.files?.[0]; // Safely access the first file
    if (!file) {
        alert("Please select a file first.");
        return;
    }

    setUploadProgress({ status: 'Slicing file...', percent: 0 });

    try {
        const chunkData = []; // Store { hash, size, chunk (Blob) }
        const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE)); // Ensure at least 1 chunk for 0-byte file
        setUploadProgress({ status: `Preparing ${totalChunks} chunk(s)...`, percent: 5 });

        if (file.size === 0) { // Handle zero-byte file explicitly
            chunkData.push({ hash: await calculateHash(new ArrayBuffer(0)), size: 0, chunk: new Blob([]) });
        } else {
            for (let i = 0; i < file.size; i += CHUNK_SIZE) {
                const chunkBlob = file.slice(i, i + CHUNK_SIZE);
                const chunkBuffer = await chunkBlob.arrayBuffer();
                const hash = await calculateHash(chunkBuffer);
                chunkData.push({ hash, size: chunkBlob.size, chunk: chunkBlob });
                // Update progress during hashing phase (up to 20%)
                setUploadProgress({
                    status: `Hashing chunk ${chunkData.length} of ${totalChunks}...`,
                    percent: Math.min(20, 5 + Math.round((chunkData.length / totalChunks) * 15))
                });
            }
        }
        const chunkHashes = chunkData.map(c => c.hash);

        setUploadProgress({ status: 'Checking server for duplicates...', percent: 25 });
        const { newChunks } = await makeApiCall('/files/check-chunks', 'POST', { chunkHashes });

        const totalNewChunks = newChunks.length;
        setUploadProgress({ status: `Uploading ${totalNewChunks} new chunk(s)...`, percent: 30 });

        // Upload *only* the new chunks to S3 using the presigned URLs
        await Promise.all(newChunks.map(async (chunkInfo, index) => {
            // Find the actual Blob data corresponding to the hash
            const chunkToUpload = chunkData.find(c => c.hash === chunkInfo.hash)?.chunk;
            if (!chunkToUpload) throw new Error(`Consistency error: Could not find chunk data for new hash ${chunkInfo.hash}`);

            // Use fetch to PUT data directly to S3 URL
            const uploadResponse = await fetch(chunkInfo.uploadUrl, {
                 method: 'PUT',
                 body: chunkToUpload,
                 // S3 presigned PUT URLs generally don't need Content-Type unless specifically required by bucket policy or lambda generating URL
                 // headers: { 'Content-Type': chunkToUpload.type || 'application/octet-stream' }
            });
            if (!uploadResponse.ok) {
                 // Try to get more info from S3 error response
                 const errorText = await uploadResponse.text().catch(() => `S3 Error ${uploadResponse.status}`);
                 throw new Error(`Failed to upload chunk ${index + 1} to S3 (${uploadResponse.status}). ${errorText}`);
            }

            // Calculate percentage based on upload progress (30% to 95%)
            const basePercent = 30;
            const range = 65; // 95 - 30
            // Prevent division by zero if totalNewChunks is 0
            const percentComplete = totalNewChunks > 0 ? basePercent + ((index + 1) / totalNewChunks) * range : basePercent;
            setUploadProgress({ status: `Uploading chunk ${index + 1} of ${totalNewChunks}...`, percent: Math.round(percentComplete) });
        }));

        // If there were no new chunks, indicate that
        if (totalNewChunks === 0 && chunkData.length > 0) {
             setUploadProgress({ status: 'All chunks already exist on server...', percent: 95 });
        } else if (totalNewChunks === 0 && chunkData.length === 0) {
             // Case for 0-byte file if it exists already
             setUploadProgress({ status: 'Zero-byte file chunk exists...', percent: 95 });
        }


        setUploadProgress({ status: 'Finalizing file assembly...', percent: 98 });
        // Tell the backend about ALL chunks (hashes) and which ones were *just* uploaded (with size)
        const newChunksForAssembly = newChunks.map(info => {
            const originalChunk = chunkData.find(c => c.hash === info.hash);
            // Ensure size is included
            return { hash: info.hash, size: originalChunk ? originalChunk.size : 0 };
        });

        await makeApiCall('/files/assemble', 'POST', {
             fileName: file.name,
             fileSize: file.size, // Send original total file size
             chunkHashes,       // Send all hashes for the file order
             newChunksUploaded: newChunksForAssembly // Send info only for chunks uploaded in *this* request
        });

        setUploadProgress({ status: 'Upload Complete!', percent: 100 });
        fetchFiles(); // Refresh file list
        if (isAdmin) fetchAdminMetrics(); // Refresh metrics if admin is viewing
        if (fileInput) fileInput.value = null; // Reset file input

    } catch (error) {
        console.error('Upload Error:', error);
        alert(`Upload failed: ${error.message}`);
        // Use a distinct state or percent value for error
        setUploadProgress({ status: `Error`, percent: -1, message: error.message });
    } finally {
         // Clear progress message after 5 seconds, unless it was an error
         // Check if uploadProgress exists before accessing percent
         if (uploadProgress && uploadProgress.percent !== -1) {
             setTimeout(() => setUploadProgress(null), 5000);
         }
         // If it was an error, keep the message longer or require manual dismissal?
         // For now, let's clear error messages too after a delay
         else if (uploadProgress && uploadProgress.percent === -1) {
             setTimeout(() => setUploadProgress(null), 10000); // Keep error visible longer
         }
    }
  };


  const handleDownload = async (fileId, fileName) => {
    setDownloadProgress({ status: `Preparing ${fileName}...`, percent: 0 });
    try {
        // Step 1: Get the list of presigned chunk URLs from our backend
        // Backend now handles checking ownership and getting chunk list
        const { downloadUrls } = await makeApiCall(`/files/download/${fileId}`);

        if (!downloadUrls || downloadUrls.length === 0) {
             // Handle empty file case: create an empty blob and download it
             const fileBlob = new Blob([]);
             triggerDownload(fileBlob, fileName);
             setDownloadProgress({ status: 'Download Complete (Empty File)!', percent: 100 });
             setTimeout(() => setDownloadProgress(null), 3000);
             return;
        }

        const totalChunksToDownload = downloadUrls.length;
        setDownloadProgress({ status: `Downloading ${totalChunksToDownload} chunk(s)...`, percent: 10 });

        // Step 2: Fetch all chunk blobs in parallel directly from S3 URLs
        const chunkBlobs = await Promise.all(downloadUrls.map(async (url, index) => {
            const response = await fetch(url); // Fetch chunk directly from S3
            if (!response.ok) {
                const errorText = await response.text().catch(() => `S3 Error ${response.status}`);
                throw new Error(`Failed to download chunk ${index + 1}: ${errorText}`);
            }
            const blob = await response.blob();
            // Calculate percentage based on download progress (10% to 95%)
            const basePercent = 10;
            const range = 85; // 95 - 10
            const percentComplete = basePercent + ((index + 1) / totalChunksToDownload) * range;
            setDownloadProgress({ status: `Downloading chunk ${index + 1} of ${totalChunksToDownload}...`, percent: Math.round(percentComplete) });
            return blob;
        }));

        setDownloadProgress({ status: 'Reassembling file...', percent: 98 });

        // Step 3: Combine blobs into a single file blob
        const fileBlob = new Blob(chunkBlobs);

        // Step 4: Trigger browser download
        triggerDownload(fileBlob, fileName);

        setDownloadProgress({ status: 'Download Complete!', percent: 100 });

    } catch (error) {
        console.error('Download Error:', error);
        alert(`Download failed: ${error.message}`);
        setDownloadProgress({ status: `Error`, percent: -1, message: error.message }); // Indicate error
    } finally {
        // Clear progress message after 5 seconds, unless it was an error
        if (downloadProgress && downloadProgress.percent !== -1) {
            setTimeout(() => setDownloadProgress(null), 5000);
        }
        // Keep error visible longer
        else if (downloadProgress && downloadProgress.percent === -1) {
             setTimeout(() => setDownloadProgress(null), 10000);
        }
    }
  };

  // Helper function to trigger browser download from a Blob
  function triggerDownload(blob, fileName) {
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = fileName; // Set the desired filename for the download
      document.body.appendChild(link); // Append needed for Firefox compatibility
      link.click(); // Programmatically click the link to trigger download
      document.body.removeChild(link); // Clean up by removing the link
      URL.revokeObjectURL(link.href); // Release the object URL to free memory
  }

  const handleShare = async (fileId) => {
      // Set initial state for the specific file being shared
      setShareLinkInfo({ fileId: fileId, link: 'Generating link...', error: '' });
      try {
          // Call backend to generate/get shareId for this file
          const data = await makeApiCall(`/files/share/${fileId}`, 'POST');
          const publicLink = getPublicShareUrl(data.shareId); // Construct full URL in frontend
          setShareLinkInfo({ fileId: fileId, link: publicLink, error: '' });
      } catch (error) {
          console.error("Share error:", error);
          setShareLinkInfo({ fileId: fileId, link: '', error: `Failed to generate link: ${error.message}` });
      }
  };

  // --- Render Components ---

  // Simple loading indicator during initial auth check
  if (isLoadingAuth) {
      return <div className="loading-indicator">Authenticating...</div>; // Add CSS for this class
  }

  // Admin Dashboard Component
  const AdminDashboard = () => (
    <div id="admin-section">
        <h2>Admin Dashboard</h2>
        {!metrics ? <p>Loading metrics...</p> : (
            <div id="metrics-summary">
                {/* Use optional chaining and nullish coalescing for safety */}
                {metrics.summary ? (
                    <>
                        <p><strong>Total Users (Cognito):</strong> {metrics.summary.totalUsers ?? 'N/A'}</p>
                        <p><strong>Total Files (Metadata):</strong> {metrics.summary.totalFiles ?? 'N/A'}</p>
                        <hr style={{margin: '10px 0'}}/>
                        <p><strong>Combined Original Size:</strong> {metrics.summary.totalOriginalMB ?? 'N/A'} MB</p>
                        <p><strong>Actual Stored Size (S3 Chunks):</strong> {metrics.summary.totalStoredMB ?? 'N/A'} MB</p>
                        <p><strong>Total Space Saved:</strong> {metrics.summary.savedMB ?? 'N/A'} MB</p>
                        <p><strong>Deduplication Ratio:</strong> {metrics.summary.deduplicationRatio ?? 'N/A'}</p>
                    </>
                ) : <p>Metrics data unavailable.</p>}
            </div>
        )}
    </div>
  );

  // Auth Forms Component
  const renderAuth = () => (
    <div id="auth-container">
      {view === 'login' && (
        <div>
          <h1>Login to Mini Drive</h1>
          <form onSubmit={handleLogin}>
            <label htmlFor="login-email">Email:</label>
            <input id="login-email" type="email" value={email} placeholder="your@email.com" required onChange={(e) => setEmail(e.target.value)} />
            <label htmlFor="login-password">Password:</label>
            <input id="login-password" type="password" value={password} placeholder="Password" required onChange={(e) => setPassword(e.target.value)} />
            <button type="submit">Login</button>
            <p>New user? <a onClick={() => setView('register')}>Register here</a></p>
          </form>
        </div>
      )}
      {view === 'register' && (
        <div>
          <h1>Register for Mini Drive</h1>
          <form onSubmit={handleRegister}>
             <label htmlFor="reg-email">Email:</label>
            <input id="reg-email" type="email" value={email} placeholder="your@email.com" required onChange={(e) => setEmail(e.target.value)} />
             <label htmlFor="reg-password">Password:</label>
            <input id="reg-password" type="password" value={password} placeholder="Password (min 8 characters)" required onChange={(e) => setPassword(e.target.value)} />
            <button type="submit">Register</button>
            <p>Already have an account? <a onClick={() => setView('login')}>Login here</a></p>
          </form>
        </div>
      )}
      {view === 'confirm' && (
        <div>
          <h2>Confirm Your Email</h2>
          <p>A confirmation code was sent to {email || 'your email'}. Please enter it below.</p>
          <form onSubmit={handleConfirm}>
            <label htmlFor="confirm-code">Confirmation Code:</label>
            <input id="confirm-code" type="text" placeholder="Enter code" required onChange={(e) => setCode(e.target.value)} />
            <button type="submit">Confirm Sign Up</button>
            <p><a onClick={() => setView('login')}>Back to Login</a></p>
            {/* Consider adding a 'Resend Code' button here that calls Amplify's resendSignUp */}
          </form>
        </div>
      )}
    </div>
  );

  // Main Dashboard Component
  const renderDashboard = () => (
    <div id="dashboard">
      <button id="logoutBtn" onClick={handleLogout}>Logout</button>
      <h1>Welcome {user?.username || 'User'}</h1>

      {isAdmin && <AdminDashboard />}

      <form onSubmit={handleUpload} className="upload-form">
        <h2>Upload New File</h2>
        {/* Associate label with input for accessibility */}
        <label htmlFor="file-input" style={{display:'block', marginBottom:'5px'}}>Select file:</label>
        <input type="file" name="file" id="file-input" required disabled={!!uploadProgress}/>
        <button type="submit" disabled={!!uploadProgress}>
          {/* Show more descriptive upload status */}
          {uploadProgress?.status && uploadProgress.percent !== -1 ? `${uploadProgress.status} (${uploadProgress.percent}%)`
           : uploadProgress?.percent === -1 ? 'Upload Failed'
           : 'Upload File'}
        </button>
        {/* Progress Bar for upload */}
        {uploadProgress && uploadProgress.percent >= 0 && (
             <progress value={uploadProgress.percent} max="100" aria-label="Upload progress"></progress>
        )}
        {/* Error message for upload */}
        {uploadProgress && uploadProgress.percent === -1 && (
             <p className="error-message">Upload Error: {uploadProgress.message || 'Unknown error'}</p>
        )}
      </form>

      {/* Progress display for download */}
      {downloadProgress && (
          <div className="progress-message">
              <p>{`${downloadProgress.status} (${downloadProgress.percent}%)`}</p>
              {downloadProgress.percent >= 0 && <progress value={downloadProgress.percent} max="100" aria-label="Download progress"></progress>}
              {downloadProgress.percent === -1 && <p className="error-message">Download Error: {downloadProgress.message || 'Unknown error'}</p>}
          </div>
      )}


      <div id="fileList">
        <h2>My Files</h2>
        {files.length === 0 ? <p>You haven't uploaded any files yet.</p> : (
          <ul>
            {files.map((file) => (
              <li key={file.fileId}>
                {/* Wrap info and actions in a div for better flex control */}
                <div className="file-item-main">
                    <span className="file-info" title={`ID: ${file.fileId}\nUploaded: ${file.uploadDate ? new Date(file.uploadDate).toLocaleString() : 'N/A'}`}>
                        {file.fileName}
                        {/* Display file size if available */}
                        <span className="file-size">
                            ({ file.fileSize !== undefined ? (file.fileSize / 1024 / 1024).toFixed(2) + ' MB' : 'Size N/A' })
                        </span>
                    </span>
                    <div className="file-actions">
                    {/* Disable buttons during any operation */}
                    <button onClick={() => handleDownload(file.fileId, file.fileName)} disabled={!!downloadProgress || !!uploadProgress}>Download</button>
                    {/* Show 'Sharing...' or similar if link is being generated for THIS file */}
                    <button onClick={() => handleShare(file.fileId)} disabled={!!uploadProgress || !!downloadProgress || (shareLinkInfo.fileId === file.fileId && shareLinkInfo.link === 'Generating link...')}>
                        {shareLinkInfo.fileId === file.fileId && shareLinkInfo.link === 'Generating link...' ? 'Sharing...' : 'Share'}
                        </button>
                    </div>
                </div>
                 {/* Display Share Link/Error specific to this file */}
                 {shareLinkInfo.fileId === file.fileId && (
                     <div className="share-link-box"> {/* Removed item-share-box, use general */}
                         {shareLinkInfo.error ? (
                             <p className="error-message">{shareLinkInfo.error}</p>
                         ) : shareLinkInfo.link.startsWith('Generating') ? (
                             <p>{shareLinkInfo.link}</p>
                         ) : (
                             <>
                                 <input type="text" value={shareLinkInfo.link} readOnly aria-label="Shareable link"/>
                                 <button
                                     onClick={() => {
                                         navigator.clipboard.writeText(shareLinkInfo.link)
                                             .then(() => alert('Link copied to clipboard!'))
                                             .catch(err => alert('Failed to copy link.'));
                                     }}
                                 >
                                     Copy
                                 </button>
                             </>
                         )}
                         <button onClick={() => setShareLinkInfo({ fileId: null, link: '', error: '' })} className="close-btn" aria-label="Close share link">&times;</button>
                     </div>
                 )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );

  // Main return statement: Show loading, auth, or dashboard
  return (
      <div>
          {isLoadingAuth ? (
              <div className="loading-indicator">Authenticating...</div>
          ) : user ? (
              renderDashboard()
          ) : (
              renderAuth()
          )}
      </div>
  );
}

export default App;

