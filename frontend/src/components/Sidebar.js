import React, { useState, useEffect, useRef } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  PanelLeftClose, PanelLeftOpen,
  Sun, Moon, User, LogOut, X, Plus,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import { useCopilotNav } from '../contexts/CopilotNavContext';
import { NAV_GROUPS, BOTTOM_ITEMS } from '../navConfig';
import CopilotConversationList from './copilot/CopilotConversationList';

const LS_COLLAPSED = 'triksha_sidebar_collapsed';

function BrandLogo() {
  return (
    <div className="flex-shrink-0 leading-tight text-left">
      <div className="text-xl font-bold text-primary-600 dark:text-primary-400">Triksha</div>
      <div className="text-[11px] font-medium text-black dark:text-white tracking-wide">
        AI Security Platform
      </div>
    </div>
  );
}

function NavRow({ item, collapsed, onNavigate }) {
  const location = useLocation();
  const Icon = item.icon;
  const matchActive = item.match
    ? location.pathname === item.match || location.pathname.startsWith(item.match + '/')
    : undefined;

  const base =
    'group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors duration-150';
  const cls = ({ isActive }) => {
    const active = matchActive !== undefined ? matchActive : isActive;
    return `${base} ${collapsed ? 'justify-center px-2' : ''} ${
      active
        ? 'bg-primary-100/80 dark:bg-primary-900/40 text-primary-700 dark:text-primary-300 hover:bg-primary-100 dark:hover:bg-primary-900/55'
        : 'text-gray-600 dark:text-gray-300 hover:bg-gray-200/80 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white'
    }`;
  };

  return (
    <NavLink
      to={item.to}
      end={item.to === '/'}
      onClick={onNavigate}
      className={cls}
      title={collapsed ? item.label : undefined}
    >
      <Icon className="h-[18px] w-[18px] flex-shrink-0" />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </NavLink>
  );
}

function SidebarPanel({ collapsed, setCollapsed, onCloseMobile, isMobile }) {
  const { user, isAdmin, logout } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const { api: copilotNav } = useCopilotNav();
  const location = useLocation();
  const navigate = useNavigate();
  const isCopilotRoute = location.pathname === '/';

  const [accountOpen, setAccountOpen] = useState(false);
  const accountRef = useRef(null);

  useEffect(() => {
    const onClick = (e) => {
      if (accountRef.current && !accountRef.current.contains(e.target)) setAccountOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, []);


  const visibleGroups = NAV_GROUPS
    .filter((grp) => !(isCopilotRoute && grp.id === 'copilot'))
    .map((grp) => ({ ...grp, items: grp.items.filter((it) => !it.adminOnly || isAdmin) }))
    .filter((grp) => grp.items.length > 0);

  const handleNewChat = () => {
    copilotNav?.newChat?.();
    onCloseMobile?.();
  };

  const handleOpenConversation = (id) => {
    copilotNav?.openConversation?.(id);
    onCloseMobile?.();
  };

  return (
    <div
      className={`flex h-full flex-col bg-gray-50 dark:bg-gray-950 border-r border-gray-200 dark:border-gray-800 transition-[width] duration-200 ${
        collapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Header / brand */}
      <div className={`flex items-center gap-2 px-3 py-3 ${collapsed ? 'justify-center' : ''}`}>
        {!collapsed && (
          <button onClick={() => navigate('/')} className="flex items-center min-w-0">
            <BrandLogo />
          </button>
        )}

        {/* Collapse toggle (desktop) / close (mobile) */}
        {isMobile ? (
          <button
            onClick={onCloseMobile}
            className="ml-auto p-1.5 rounded-lg text-gray-500 hover:bg-gray-200 dark:hover:bg-gray-800"
            aria-label="Close menu"
          >
            <X className="h-5 w-5" />
          </button>
        ) : (
          <button
            onClick={() => setCollapsed((c) => !c)}
            className={`${collapsed ? '' : 'ml-auto'} p-1.5 rounded-lg text-gray-500 hover:bg-gray-200 dark:hover:bg-gray-800`}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
          </button>
        )}
      </div>

      {/* New chat — Copilot home only (Claude-style top action) */}
      {isCopilotRoute && copilotNav && (
        <div className={`flex-shrink-0 px-2 pb-2 ${collapsed ? 'flex justify-center' : ''}`}>
          <button
            type="button"
            onClick={handleNewChat}
            className={`flex items-center gap-2 rounded-lg bg-primary-600 text-white text-sm font-semibold
              hover:bg-primary-500 transition-colors duration-150 ${collapsed ? 'p-2.5' : 'w-full px-3 py-2'}`}
            title={collapsed ? 'New chat' : undefined}
          >
            <Plus className="h-4 w-4 flex-shrink-0" />
            {!collapsed && <span>New chat</span>}
          </button>
        </div>
      )}

      {/* Product navigation */}
      <nav className={`px-2 space-y-1 ${isCopilotRoute && copilotNav ? 'flex-shrink-0 pb-3' : 'flex-1 overflow-y-auto scrollbar-thin pb-2'}`}>
        {visibleGroups.map((grp) => (
          <div key={grp.id} className="pt-1">
            {grp.label && !collapsed && (
              <div className="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500">
                {grp.label}
              </div>
            )}
            <div className="space-y-0.5">
              {grp.items.map((it) => (
                <NavRow key={it.to} item={it} collapsed={collapsed} onNavigate={onCloseMobile} />
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* Recents — Copilot home only; fills remaining height */}
      {isCopilotRoute && copilotNav && !collapsed && (
        <div className="flex flex-col min-h-0 flex-1 mt-2 pt-4 border-t border-gray-200 dark:border-gray-800">
          <CopilotConversationList
            conversations={copilotNav.conversations || []}
            activeId={copilotNav.activeId}
            onOpen={handleOpenConversation}
            onRename={copilotNav.onRename}
            onDelete={copilotNav.onDelete}
          />
        </div>
      )}

      {/* Bottom: pinned items + theme + account */}
      <div className="border-t border-gray-200 dark:border-gray-800 px-2 py-2 space-y-0.5">
        {BOTTOM_ITEMS.map((it) => (
          <NavRow key={it.to} item={it} collapsed={collapsed} onNavigate={onCloseMobile} />
        ))}

        <button
          onClick={toggleTheme}
          className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-gray-600 dark:text-gray-300 transition-colors duration-150 hover:bg-gray-200/80 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white ${
            collapsed ? 'justify-center px-2' : ''
          }`}
          title={collapsed ? (isDark ? 'Light mode' : 'Dark mode') : undefined}
        >
          {isDark ? <Sun className="h-[18px] w-[18px]" /> : <Moon className="h-[18px] w-[18px]" />}
          {!collapsed && <span>{isDark ? 'Light mode' : 'Dark mode'}</span>}
        </button>

        {/* Account */}
        <div className="relative" ref={accountRef}>
          <button
            onClick={() => setAccountOpen((o) => !o)}
            className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 transition-colors duration-150 hover:bg-gray-200/80 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white ${
              collapsed ? 'justify-center px-2' : ''
            }`}
            title={collapsed ? (user?.id || user?.name || 'Account') : undefined}
          >
            <span className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900">
              <User className="h-4 w-4 text-primary-600 dark:text-primary-400" />
            </span>
            {!collapsed && (
              <span className="flex-1 truncate text-left">{user?.id || user?.name || 'Account'}</span>
            )}
          </button>

          {accountOpen && (
            <div className="absolute bottom-full left-0 mb-2 w-52 rounded-lg bg-white dark:bg-gray-800 py-1 shadow-lg ring-1 ring-black/5 dark:ring-gray-700 z-50">
              <div className="px-3 py-2 border-b border-gray-100 dark:border-gray-700">
                <div className="text-sm font-medium text-gray-800 dark:text-gray-100 truncate">{user?.id || user?.name}</div>
                {user?.email && <div className="text-xs text-gray-500 dark:text-gray-400 truncate">{user.email}</div>}
              </div>
              <button
                onClick={logout}
                className="flex w-full items-center px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                <LogOut className="mr-3 h-4 w-4" /> Sign out
              </button>
            </div>
          )}
        </div>
      </div>

    </div>
  );
}

export default function Sidebar({ mobileOpen, onCloseMobile }) {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(LS_COLLAPSED) === '1'
  );
  useEffect(() => {
    localStorage.setItem(LS_COLLAPSED, collapsed ? '1' : '0');
  }, [collapsed]);

  return (
    <>
      {/* Desktop: static rail */}
      <div className="hidden md:flex flex-shrink-0">
        <SidebarPanel collapsed={collapsed} setCollapsed={setCollapsed} isMobile={false} />
      </div>

      {/* Mobile: overlay drawer (always expanded width) */}
      {mobileOpen && (
        <div className="md:hidden fixed inset-0 z-50 flex">
          <div className="absolute inset-0 bg-black/40" onClick={onCloseMobile} />
          <div className="relative z-50">
            <SidebarPanel
              collapsed={false}
              setCollapsed={() => {}}
              onCloseMobile={onCloseMobile}
              isMobile
            />
          </div>
        </div>
      )}
    </>
  );
}
