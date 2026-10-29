import React, { useState, useEffect } from 'react';

const TrikshaAnimation = ({ onComplete }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [textIndex, setTextIndex] = useState(0);
  const [showSubtitle, setShowSubtitle] = useState(false);

  useEffect(() => {
    setIsVisible(true);
    
    // Type out "Triksha" letter by letter
    const textInterval = setInterval(() => {
      setTextIndex(prev => {
        if (prev < 6) { // "Triksha" has 7 letters
          return prev + 1;
        } else {
          clearInterval(textInterval);
          // Show subtitle after text is complete
          setTimeout(() => setShowSubtitle(true), 200);
          return prev;
        }
      });
    }, 120);

    // Complete animation after 2.5 seconds
    const completeTimer = setTimeout(() => {
      setIsVisible(false);
      onComplete();
    }, 2500);

    return () => {
      clearInterval(textInterval);
      clearTimeout(completeTimer);
    };
  }, [onComplete]);

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 bg-white flex items-center justify-center z-50">
      <div className="text-center">
        {/* Main Logo */}
        <div className="mb-6">
          <div className="w-16 h-16 mx-auto mb-4 flex items-center justify-center">
            {/* Simple Triksha logo - security shield */}
            <svg className="w-16 h-16" viewBox="0 0 24 24" fill="none">
              {/* Security shield */}
              <path d="M12 2L8 4V10C8 14 12 18 12 18S16 14 16 10V4L12 2Z" fill="#2874F0"/>
              
              {/* Simple 'T' for Triksha */}
              <text x="12" y="16" textAnchor="middle" fontSize="8" fill="white" fontWeight="bold" fontFamily="Arial, sans-serif">T</text>
            </svg>
          </div>
        </div>

        {/* Animated Text */}
        <div className="mb-4">
          <h1 className="text-4xl md:text-5xl font-bold text-gray-900 tracking-tight">
            {['T', 'R', 'I', 'K', 'S', 'H', 'A'].map((letter, index) => (
              <span
                key={index}
                className={`inline-block transition-all duration-300 ${
                  index <= textIndex 
                    ? 'opacity-100 translate-y-0' 
                    : 'opacity-0 translate-y-2'
                }`}
                style={{
                  transitionDelay: `${index * 80}ms`
                }}
              >
                {letter}
              </span>
            ))}
          </h1>
        </div>

        {/* Subtitle */}
        {showSubtitle && (
          <div className="animate-fade-in">
            <p className="text-lg text-gray-600 font-light tracking-wide">
              AI Security Platform
            </p>
          </div>
        )}

        {/* Minimal Loading Indicator */}
        <div className="mt-8">
          <div className="w-1 h-8 bg-gray-300 mx-auto rounded-full overflow-hidden">
            <div 
              className="w-full h-full bg-gray-900 rounded-full animate-loading-bar"
              style={{
                animation: 'loadingBar 2.5s ease-out forwards'
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default TrikshaAnimation;
