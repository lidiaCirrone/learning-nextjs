import Link from 'next/link';
import { FaceFrownIcon } from '@heroicons/react/24/outline';

/* 
* Another way you can handle errors gracefully is by using 
* the notFound function. While error.tsx is useful for catching 
* all errors, notFound can be used when you try to fetch 
* a resource that doesn't exist.
* `notFound` will take precedence over error.tsx, so you can reach out 
* for it when you want to handle more specific errors!
*/

export default function NotFound() {
   return (
      <main className="flex h-full flex-col items-center justify-center gap-2">
         <FaceFrownIcon className="w-10 text-gray-400" />
         <h2 className="text-xl font-semibold">404 Not Found</h2>
         <p>Could not find the requested invoice.</p>
         <Link
            href="/dashboard/invoices"
            className="mt-4 rounded-md bg-blue-500 px-4 py-2 text-sm text-white transition-colors hover:bg-blue-400"
         >
            Go Back
         </Link>
      </main>
   );
}