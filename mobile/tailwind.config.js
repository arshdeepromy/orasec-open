/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
    // Konsta v5 components emit Tailwind utility classes (bg-md-*, hairline-*,
    // touch-ripple-*, translate/duration helpers). Tailwind must scan the
    // library source or none of those utilities are generated and every
    // Konsta component renders unstyled/mis-laid-out.
    './node_modules/konsta/react/**/*.{js,mjs}',
    './node_modules/konsta/shared/**/*.{js,mjs}',
    './node_modules/konsta/styles/**/*.{js,mjs}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: 'var(--color-primary, #2563EB)',
        secondary: 'var(--color-secondary, #1E40AF)',
      },
    },
  },
  plugins: [],
}
