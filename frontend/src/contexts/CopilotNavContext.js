import React, { createContext, useContext, useState } from 'react';

/**
 * Bridges TrikshaCopilot conversation state into the app-level Sidebar so the
 * Copilot home route uses one unified rail (nav + recents), Claude-style.
 */
const CopilotNavContext = createContext({ api: null, setApi: () => {} });

export function CopilotNavProvider({ children }) {
  const [api, setApi] = useState(null);
  return (
    <CopilotNavContext.Provider value={{ api, setApi }}>
      {children}
    </CopilotNavContext.Provider>
  );
}

export function useCopilotNav() {
  return useContext(CopilotNavContext);
}
