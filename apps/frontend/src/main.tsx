import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from '@/App';
import '@/style.css';

// The page has no markup of its own: the HTML file only holds this element.
const root = document.getElementById('root');
if (!root) {
  throw new Error('The page has no #root element.');
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
