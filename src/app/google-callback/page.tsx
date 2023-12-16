'use client';

import { useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';
import { loginOrRegisterWithGoogleCode } from '../actions';

export default function GoogleCallback() {
  const searchParams = useSearchParams();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = searchParams.get('code');
    if (!code) {
      setError('No code found in the URL parameters.');
      return;
    }

    loginOrRegisterWithGoogleCode(code);
  }, [searchParams]);

  return <div>{error ? <p>Error: {error}</p> : <p>Authenticating...</p>}</div>;
}
