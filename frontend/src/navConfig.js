// Single source of truth for the app's left-sidebar navigation.
import {
  Sparkles, Brain, Bot, Network,
  Database, FlaskConical, FileSearch,
  ShieldCheck, Plug, Settings as SettingsIcon,
} from 'lucide-react';

export const NAV_GROUPS = [
  {
    id: 'copilot',
    label: null,
    items: [
      { to: '/', label: 'Copilot', icon: Sparkles },
    ],
  },
  {
    id: 'modules',
    label: 'Modules',
    items: [
      { to: '/models',   label: 'LLMs',         icon: Brain },
      { to: '/agents',   label: 'Agents',        icon: Bot },
      { to: '/mcps',     label: 'MCPs',          icon: Network },
      { to: '/datasets', label: 'Datasets',      icon: Database },
      { to: '/prd',      label: 'PRD Reviewer',    icon: FileSearch },
      { to: '/harden',   label: 'Prompt Hardener', icon: ShieldCheck },
      { to: '/sandbox',  label: 'Sandbox',         icon: FlaskConical },
    ],
  },
];

export const BOTTOM_ITEMS = [
  { to: '/connectors', label: 'Connectors', icon: Plug },
  { to: '/settings',   label: 'Settings',   icon: SettingsIcon },
];

export const FULL_BLEED_ROUTES = ['/'];
