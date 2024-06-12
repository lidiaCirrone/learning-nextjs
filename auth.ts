import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

/* After validating the credentials, create a new getUser function 
that queries the user from the database. */
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  /* The Credentials provider allows users to log in with a username and a password. 
  Although we're using the Credentials provider, it's generally recommended 
  to use alternative providers such as OAuth or email providers. 
  See the NextAuth.js docs for a full list of options.*/
  providers: [
    Credentials({
      /* You can use the authorize function to handle the authentication logic. 
    Similarly to Server Actions, you can use zod to validate the email and password 
    before checking if the user exists in the database: */
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;
          /* Then, call bcrypt.compare to check if the passwords match. 
          If the passwords match you want to return the user, otherwise, return null 
          to prevent the user from logging in. */
          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) return user;
        }

        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});
