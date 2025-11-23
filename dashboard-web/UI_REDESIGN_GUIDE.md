# RAG Wazuh Dashboard - Unique UI Redesign
## "Command Center" Aesthetic

This guide outlines the complete redesign to create an **iconic, non-AI-looking professional dashboard** with:
- Hexagonal/geometric design language
- Neon accent glows
- Terminal/HUD-inspired typography
- Diagonal accents and unconventional layouts
- Custom data visualizations

---

## ✅ COMPLETED: Design Tokens (tailwind.config.js)

**New Color Palette:**
- `command.*` - Deep space backgrounds
- `neon.*` - Neon accent colors (cyan, magenta, lime, amber)
- Updated severity colors with neon variants
- Added `glow` and `bg` variants for each severity

**New Animations:**
- `glow-pulse` - Neon pulsing effect
- `scan-line` - CRT scan line animation
- `slide-in-right/left` - Entrance animations
- `fade-in-up` - Fade and rise
- `hexagon-pulse` - Hexagon breathing effect

**Custom Patterns:**
- `bg-hex-pattern` - Hexagonal background
- `bg-grid-pattern` - Grid overlay

---

## 🎨 CSS UPDATES NEEDED

### File: `src/index.css`

Replace entire file with:

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Import fonts for terminal aesthetic */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

@layer base {
  * {
    @apply border-command-border;
  }
  body {
    @apply bg-command-void text-gray-100 antialiased font-sans;
  }
}

@layer utilities {
  /* Neon glow effects */
  .neon-glow-cyan {
    box-shadow: 0 0 10px rgba(0, 240, 255, 0.5),
                0 0 20px rgba(0, 240, 255, 0.3),
                0 0 30px rgba(0, 240, 255, 0.2);
  }

  .neon-glow-critical {
    box-shadow: 0 0 10px rgba(255, 8, 68, 0.5),
                0 0 20px rgba(255, 8, 68, 0.3);
  }

  /* Terminal-style text */
  .terminal-text {
    font-family: 'JetBrains Mono', monospace;
    text-shadow: 0 0 5px currentColor;
    letter-spacing: 0.05em;
  }

  /* Hexagon shape */
  .hexagon {
    clip-path: polygon(30% 0%, 70% 0%, 100% 50%, 70% 100%, 30% 100%, 0% 50%);
  }

  /* Grid background */
  .command-grid {
    background-image:
      linear-gradient(rgba(35, 41, 55, 0.5) 1px, transparent 1px),
      linear-gradient(90deg, rgba(35, 41, 55, 0.5) 1px, transparent 1px);
    background-size: 20px 20px;
  }
}

/* Neon scrollbar */
::-webkit-scrollbar {
  width: 6px;
}

::-webkit-scrollbar-track {
  @apply bg-command-surface;
}

::-webkit-scrollbar-thumb {
  @apply bg-info;
  border-radius: 10px;
  box-shadow: 0 0 6px rgba(0, 240, 255, 0.5);
}

/* HUD-style panel */
.hud-panel {
  position: relative;
  background: linear-gradient(135deg,
    rgba(17, 24, 39, 0.95) 0%,
    rgba(26, 31, 46, 0.90) 100%);
  border: 1px solid #232937;
  backdrop-filter: blur(10px);
}

.hud-panel::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg,
    transparent 0%,
    rgba(0, 240, 255, 0.5) 50%,
    transparent 100%);
}

/* Stat card with diagonal */
.stat-card {
  position: relative;
  background: linear-gradient(135deg, #111827 0%, #1a1f2e 100%);
  border: 1px solid #232937;
  overflow: hidden;
}

.stat-card::after {
  content: '';
  position: absolute;
  top: 0;
  right: 0;
  width: 100px;
  height: 100%;
  background: linear-gradient(135deg, transparent 0%, rgba(0, 240, 255, 0.05) 100%);
  clip-path: polygon(0 0, 100% 0, 100% 100%, 30% 100%);
}

/* Table hover effect */
table tbody tr:hover {
  background: rgba(0, 240, 255, 0.05);
  border-left: 2px solid #00f0ff;
}

/* Neon button effect */
.btn-neon {
  position: relative;
  overflow: hidden;
}

.btn-neon::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg,
    transparent,
    rgba(0, 240, 255, 0.3),
    transparent);
  transition: left 0.5s ease;
}

.btn-neon:hover::before {
  left: 100%;
}

/* Input focus */
input:focus, select:focus {
  outline: none;
  border-color: #00f0ff;
  box-shadow: 0 0 0 2px rgba(0, 240, 255, 0.2),
              0 0 10px rgba(0, 240, 255, 0.3);
}
```

---

## 🏗️ COMPONENT UPDATES

### 1. Layout Component (`src/components/Layout.tsx`)

**Key Changes:**
- Vertical sidebar with neon accent border
- Hexagonal logo background
- Terminal-style branding
- Neon status indicator

**Replace sidebar section with:**

```tsx
<aside className="w-72 bg-command-deep border-r-2 border-info/20 flex flex-col relative overflow-hidden">
  {/* Hexagon pattern background */}
  <div className="absolute inset-0 bg-hex-pattern opacity-10 pointer-events-none"></div>

  {/* Logo */}
  <div className="p-6 border-b border-command-border relative z-10">
    <Link to="/" className="flex items-center space-x-4 group">
      <div className="relative w-14 h-14">
        <div className="absolute inset-0 hexagon bg-gradient-to-br from-info/20 to-neon-magenta/20 animate-glow-pulse"></div>
        <div className="absolute inset-1 hexagon bg-command-surface flex items-center justify-center">
          <Shield className="w-7 h-7 text-info" />
        </div>
        <Activity className="w-4 h-4 text-critical absolute bottom-0 right-0 animate-pulse" />
      </div>
      <div>
        <h1 className="text-2xl font-bold terminal-text text-white tracking-wider">
          RAG<span className="text-info">_</span>WAZUH
        </h1>
        <p className="text-xs text-gray-400 font-mono uppercase tracking-widest">
          Threat Analysis
        </p>
      </div>
    </Link>
  </div>

  {/* Navigation */}
  <nav className="flex-1 p-4 space-y-2 relative z-10">
    {navItems.map((item) => {
      const Icon = item.icon;
      const isActive = location.pathname === item.path;
      return (
        <Link
          key={item.path}
          to={item.path}
          className={cn(
            'flex items-center space-x-3 px-4 py-3.5 rounded transition-all relative overflow-hidden group',
            isActive
              ? 'bg-info/10 text-info border border-info/30 neon-glow-cyan'
              : 'text-gray-400 hover:text-gray-200 hover:bg-command-hover border border-transparent'
          )}
        >
          {isActive && (
            <div className="absolute left-0 top-0 bottom-0 w-1 bg-info animate-glow-pulse"></div>
          )}
          <Icon className="w-5 h-5 relative z-10" />
          <span className="font-medium font-mono uppercase text-sm tracking-wide relative z-10">
            {item.label}
          </span>
        </Link>
      );
    })}
  </nav>

  {/* Footer - System Status */}
  <div className="p-4 border-t border-command-border bg-command-surface/50 relative z-10">
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs font-mono">
        <span className="text-gray-500 uppercase">System</span>
        <span className="text-low flex items-center space-x-2">
          <span className="w-2 h-2 bg-low rounded-full animate-pulse neon-glow-low"></span>
          <span>ONLINE</span>
        </span>
      </div>
      <div className="flex items-center justify-between text-xs font-mono">
        <span className="text-gray-500 uppercase">Ver</span>
        <span className="text-info">1.0.0</span>
      </div>
    </div>
  </div>
</aside>
```

---

### 2. StatsCard Component (`src/components/StatsCard.tsx`)

**New Design with Diagonal Accent:**

```tsx
interface StatsCardProps {
  title: string;
  value: string | number;
  icon: React.ElementType;
  trend?: string;
  color: 'info' | 'critical' | 'high' | 'medium' | 'low';
}

export default function StatsCard({ title, value, icon: Icon, trend, color }: StatsCardProps) {
  const colorClasses = {
    info: 'text-info border-info/30 neon-glow-cyan',
    critical: 'text-critical border-critical/30 neon-glow-critical',
    high: 'text-high border-high/30 neon-glow-high',
    medium: 'text-medium border-medium/30 neon-glow-medium',
    low: 'text-low border-low/30 neon-glow-low',
  };

  return (
    <div className="stat-card p-6 rounded-lg animate-fade-in-up hover:scale-105 transition-transform">
      <div className="flex items-start justify-between relative z-10">
        <div className="flex-1">
          <p className="text-gray-400 text-xs font-mono uppercase tracking-wider mb-2">
            {title}
          </p>
          <p className={`text-4xl font-bold terminal-text mb-2 ${colorClasses[color]}`}>
            {value}
          </p>
          {trend && (
            <p className="text-gray-500 text-xs font-mono">
              {trend}
            </p>
          )}
        </div>
        <div className={`p-4 rounded-lg border-2 ${colorClasses[color]} bg-${color}-bg`}>
          <Icon className="w-8 h-8" />
        </div>
      </div>
    </div>
  );
}
```

---

### 3. Dashboard Header

**Replace header section with:**

```tsx
<div className="flex items-center justify-between mb-8">
  <div>
    <div className="flex items-center space-x-4">
      <h1 className="text-4xl font-bold terminal-text text-white">
        COMMAND<span className="text-info">_</span>CENTER
      </h1>
      <div className="px-3 py-1 bg-info/10 border border-info/30 rounded-full">
        <span className="text-info text-xs font-mono uppercase tracking-wider">
          LIVE
        </span>
      </div>
    </div>
    <p className="text-gray-400 font-mono text-sm mt-2">
      AI-Powered Threat Intelligence • Predictive Analysis
    </p>
  </div>
  <button
    onClick={loadData}
    className="btn-neon flex items-center space-x-2 px-6 py-3 bg-command-panel border-2 border-info/30 rounded-lg transition-all hover:border-info hover:shadow-lg hover:shadow-info/20"
  >
    <RefreshCw className="w-5 h-5 text-info" />
    <span className="font-mono uppercase tracking-wide text-info">Refresh</span>
  </button>
</div>
```

---

### 4. Table Design

**Update table styling:**

```tsx
<div className="hud-panel rounded-lg overflow-hidden">
  <div className="p-6 border-b border-command-border">
    <h2 className="text-2xl font-bold terminal-text text-white uppercase tracking-wider">
      Threat<span className="text-info">_</span>Reports
    </h2>
  </div>

  <div className="overflow-x-auto">
    <table className="w-full">
      <thead className="bg-command-surface border-b-2 border-info/20">
        <tr>
          <th className="px-6 py-4 text-left text-xs font-mono text-info uppercase tracking-widest">
            ID
          </th>
          {/* ... more headers ... */}
        </tr>
      </thead>
      <tbody className="divide-y divide-command-border">
        {/* Table rows with hover effects from CSS */}
      </tbody>
    </table>
  </div>
</div>
```

---

## 🎯 KEY DESIGN PRINCIPLES

1. **Typography:**
   - Headers: `terminal-text` class (JetBrains Mono)
   - Labels: `font-mono uppercase tracking-wider`
   - Body: Inter font

2. **Colors:**
   - Primary: `info` (neon cyan)
   - Backgrounds: `command-*` palette
   - Accents: Neon severity colors

3. **Spacing:**
   - Use diagonal cuts and hexagons
   - Add neon glows to interactive elements
   - Grid/hex patterns in backgrounds

4. **Animations:**
   - Glow pulse on important elements
   - Slide-in animations for panels
   - Hover effects with neon borders

5. **Interactive Elements:**
   - All buttons get `btn-neon` class
   - Tables have neon left border on hover
   - Inputs have neon focus rings

---

## 🚀 IMPLEMENTATION ORDER

1. ✅ Update Tailwind config
2. ⏳ Update `index.css`
3. ⏳ Update `Layout.tsx`
4. ⏳ Update `StatsCard.tsx`
5. ⏳ Update `Dashboard.tsx` header and tables
6. ⏳ Test and refine

This design will be **instantly recognizable** and **professional**, not generic AI-generated!
