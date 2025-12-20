import { useEffect, useState } from 'react';
import { Button, ColumnLayout, Header, PromptInput, SpaceBetween, TextContent } from '@cloudscape-design/components';

interface UserInfo {
  user_id: string;
  username?: string;
  context_title?: string;
}

const LtiHandler = () => {
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [value, setValue] = useState<string>("This text contains information to translate");

  useEffect(() => {
    // Extract token from URL hash
    const hash = window.location.hash;
    const tokenMatch = hash.match(/token=([^&]+)/);
    
    if (!tokenMatch) {
      setError('No authentication token found. Please launch from Moodle.');
      setLoading(false);
      return;
    }
    
    const token = tokenMatch[1];
    
    // Clear token from URL immediately
    window.history.replaceState(null, '', window.location.pathname);
    
    // Fetch user info with token (one-time use)
    fetch('/api/user/info', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
      .then(response => {
        if (!response.ok) {
          throw new Error('Authentication failed');
        }
        return response.json();
      })
      .then(data => {
        // Store token in sessionStorage for subsequent requests
        sessionStorage.setItem('lti_token', data.token);
        setUserInfo(data);
        setLoading(false);
      })
      .catch(() => {
        setError('Authentication failed. Please launch from Moodle.');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return <div className="error">{error}</div>;
  }

  return (
    <div>
      {userInfo && (
        <div>
          <h2>User Information</h2>
          <ColumnLayout  columns={2} variant="text-grid">
            <p><strong>User ID:</strong> {userInfo.user_id}</p>
            <p><strong>Course:</strong> {userInfo.context_title}</p>
          </ColumnLayout>
        </div>
      )}
      <br />
      <div>
        <SpaceBetween size="s">
          <h2>Translation tool</h2>
          <PromptInput
            onChange={({ detail }) => setValue(detail.value)}
            value={value}
            ariaLabel="Default prompt input"
            placeholder="Enter a text to translate to French"
          />
          <Header actions={<Button variant='primary' onClick={() => console.log("Translate!")}>Translate</Button>} />
        </SpaceBetween>
        <Header variant="h3">Result:</Header> 
        <TextContent>Ce texte contient des informations à traduire</TextContent>
      </div>
    </div>
  );
};

export default LtiHandler;
