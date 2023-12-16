'use server';

import { cookies } from 'next/headers';
import * as jose from 'jose';
import User, { UserDocument } from '@/models/User';
import connect from '@/utils/db';
import { redirect } from 'next/navigation';

export const handleGoogleSignIn = () => {
  const googleClientId = process.env.googleClientId;
  const redirectUri = process.env.redirectUri; // URL de redirection
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${googleClientId}&redirect_uri=${redirectUri}&response_type=code&scope=email%20profile`;

  redirect(authUrl);
};

export const loginOrRegisterWithGoogleCode = async code => {
  try {
    const response = await fetch('/google-callback', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ code }),
    });

    const data = await response.json();
    if (response.ok) {
      setAuthCookie(data.accessToken);
    } else {
      throw new Error(data.error);
    }
  } catch (error) {
    console.error('Failed to login or register with Google code:', error);
  }
};

export const setAuthCookie = (token: string): void => {
  cookies().set('authToken', token);
  redirect('/');
};

export const deleteAuthCookie = (): void => {
  cookies().delete('authToken');
  redirect('/login');
};

export const extractJwtTokenFromCookie = (): string | null => {
  const cookieStore = cookies();
  const cookie = cookieStore.get('authToken');
  const jwt = cookie?.value;
  return jwt || null;
};

export const extractUserIdFromJwt = async (jwt: string): Promise<string | null> => {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET || '');
  try {
    const { payload } = await jose.jwtVerify(jwt, secret);
    return payload.uid as string;
  } catch (err: any) {
    console.error(err);
    return null;
  }
};

export const getUserDocumentFromUserId = async (userId: string): Promise<UserDocument | null> => {
  await connect();
  try {
    const user = await User.findOne({ _id: userId }, { _id: 1, email: 1 });
    return JSON.parse(JSON.stringify(user)); // This weird thing is here to be sure user is a json object and not a mongoose document
  } catch (err: any) {
    console.error(err);
    return null;
  }
};

export const getLoggedUserId = async (): Promise<string | null> => {
  const jwt = extractJwtTokenFromCookie();
  if (!jwt) return null;
  const userId = await extractUserIdFromJwt(jwt);
  return userId;
};

export const getLoggedUserDocument = async (): Promise<UserDocument | null> => {
  const userId = await getLoggedUserId();
  if (!userId) return null;
  const user = await getUserDocumentFromUserId(userId);
  return user;
};
