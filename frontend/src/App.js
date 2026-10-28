import React from 'react';
import { BrowserRouter as Router } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Demo from './pages/Demo';
import './index.css';

export default function App() {
  return (
    <Router>
      <Demo />
      <Toaster position="top-center" />
    </Router>
  );
}
