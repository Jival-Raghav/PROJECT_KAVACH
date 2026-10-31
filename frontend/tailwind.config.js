/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          900: '#050816',
          800: '#091122',
          700: '#12213f'
        }
      }
    }
  },
  plugins: []
}
