import { useEffect, useState } from 'react';
import { Button, ColumnLayout, Header, PromptInput, SpaceBetween, TextContent, Spinner, Alert, Container } from '@cloudscape-design/components';

// LTI 1.3 context claim (https://purl.imsglobal.org/spec/lti/claim/context)
interface LtiContext {
  id: string;
  label?: string;
  title?: string;
  type?: string[];
}

interface UserInfo {
  user_id: string;
  username?: string;
  context_title?: string;
  context?: LtiContext;
}

const MISSING_TOKEN_ERROR = 'No authentication token found. Please launch from Moodle.';

const getTokenFromHash = (): string | null =>
  window.location.hash.match(/token=([^&]+)/)?.[1] ?? null;

const LtiHandler = () => {
  // Read the token during the first render so the "no token" case is initial
  // state rather than a synchronous setState inside the effect.
  const [token] = useState<string | null>(getTokenFromHash);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState<boolean>(token !== null);
  const [error, setError] = useState<string | null>(token ? null : MISSING_TOKEN_ERROR);
  const [value, setValue] = useState<string>("This text contains information to translate");

  useEffect(() => {
    if (!token) {
      return;
    }

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
        setUserInfo(data);
        setLoading(false);
      })
      .catch(() => {
        setError('Authentication failed. Please launch from Moodle.');
        setLoading(false);
      });
  }, [token]);

  if (loading) {
    return <Spinner size="large" />;
  }

  if (error) {
    return <Alert type="error" header="Authentication Error">{error}</Alert>;
  }

  return (
    <Container>
      <SpaceBetween size="l">
        {userInfo && (
          <div>
            <Header variant="h2">User Information</Header>
            <ColumnLayout columns={2} variant="text-grid">
              <div><strong>User ID:</strong> {userInfo.user_id}</div>
              <div><strong>Course:</strong> {userInfo.context_title || 'N/A'}</div>
              {userInfo.context?.id && (
                <div><strong>Context ID:</strong> {userInfo.context.id}</div>
              )}
            </ColumnLayout>
          </div>
        )}
        
        <div>
          <SpaceBetween size="s">
            <Header variant="h2">Translation tool</Header>
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
      </SpaceBetween>
    </Container>
  );
};

export default LtiHandler;
