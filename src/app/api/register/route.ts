import User from '@/models/User';
import connect from '@/utils/db';
import bcrypt from 'bcryptjs';
import { NextResponse } from 'next/server';

export const POST = async (request: any) => {
  const { email, password } = await request.json();

  if (!/^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i.test(email)) {
    return NextResponse.json(
      { errorString: 'Email is invalid' },
      {
        status: 400,
      }
    );
  }

  if (!password || password.length < 8 || password.length > 32) {
    return NextResponse.json(
      { errorString: 'Password must be between 8 and 32 characters long' },
      {
        status: 400,
      }
    );
  }

  if (!/\d/.test(password)) {
    return NextResponse.json(
      { errorString: 'Password must contain at least one number' },
      {
        status: 400,
      }
    );
  }

  if (!/[a-z]/.test(password)) {
    return NextResponse.json(
      { errorString: 'Password must contain at least one lowercase letter' },
      {
        status: 400,
      }
    );
  }

  if (!/[A-Z]/.test(password)) {
    return NextResponse.json(
      { errorString: 'Password must contain at least one uppercase letter' },
      {
        status: 400,
      }
    );
  }

  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return NextResponse.json(
      { errorString: 'Password must contain at least one special character' },
      {
        status: 400,
      }
    );
  }

  if (/\s/.test(password)) {
    return NextResponse.json(
      { errorString: 'Password cannot contain spaces' },
      {
        status: 400,
      }
    );
  }

  await connect();

  const existingUser = await User.findOne({ email });

  if (existingUser) {
    return NextResponse.json(
      { errorString: 'Email is already in use' },
      {
        status: 400,
      }
    );
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  const newUser = new User({
    email,
    password: hashedPassword,
  });

  try {
    await newUser.save();
    return new NextResponse('', { status: 200 });
  } catch (err: any) {
    return new NextResponse(err, {
      status: 500,
    });
  }
};
