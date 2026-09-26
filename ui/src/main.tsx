import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { LazyMotion, MotionConfig, domAnimation } from './motion';
import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {/* reducedMotion="user": people who ask the OS for less motion get no
        transform or layout animation. strict: a stray full `motion.div`
        would pull in every feature bundle and throw here, not ship. */}
    <MotionConfig reducedMotion="user">
      <LazyMotion features={domAnimation} strict>
        <App />
      </LazyMotion>
    </MotionConfig>
  </StrictMode>,
);
