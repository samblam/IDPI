# ThreatStream Dashboard

Modern, real-time threat intelligence dashboard built with React, TypeScript, and TailwindCSS.

## Features

- **Real-time Threat Feed**: Live Server-Sent Events (SSE) stream of new threat indicators
- **Interactive Statistics**: Visual charts showing indicator distribution by type
- **Advanced Search**: Full-text search with type and confidence filtering
- **Indicator Details**: Detailed modal views with MITRE ATT&CK TTPs and enrichment data
- **Responsive Design**: Mobile-friendly interface with dark mode support
- **Type-Safe**: Built with TypeScript for enhanced developer experience

## Technology Stack

- **React 18**: Modern UI framework with hooks
- **TypeScript**: Static typing for better code quality
- **Vite**: Next-generation build tool for fast development
- **TailwindCSS 3**: Utility-first CSS framework
- **Recharts**: Data visualization library
- **Lucide React**: Beautiful icon library
- **date-fns**: Modern JavaScript date utility library

## Prerequisites

- Node.js 18+ and npm
- ThreatStream API running (see `../ingestion/` directory)
- API key for ThreatStream API

## Installation

### 1. Install Dependencies

```bash
cd dashboard
npm install
```

### 2. Configure Environment

Create a `.env` file in the dashboard directory:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
VITE_API_BASE_URL=http://localhost:8000
VITE_API_KEY=your-api-key-here
```

**Environment Variables**:
- `VITE_API_BASE_URL`: ThreatStream API base URL (default: `http://localhost:8000`)
- `VITE_API_KEY`: Your API key for authentication

## Development

### Start Development Server

```bash
npm run dev
```

The dashboard will be available at `http://localhost:5173`

### Build for Production

```bash
npm run build
```

Output will be in the `dist/` directory.

### Preview Production Build

```bash
npm run preview
```

## Project Structure

```
dashboard/
├── public/              # Static assets
├── src/
│   ├── components/      # React components
│   │   ├── Header.tsx
│   │   ├── StatCard.tsx
│   │   ├── IndicatorCard.tsx
│   │   ├── IndicatorModal.tsx
│   │   ├── IndicatorTypeChart.tsx
│   │   ├── SearchFilters.tsx
│   │   └── RealTimeFeed.tsx
│   ├── pages/           # Page components
│   │   └── Dashboard.tsx
│   ├── services/        # API client services
│   │   └── api.ts
│   ├── types/           # TypeScript type definitions
│   │   └── api.ts
│   ├── App.tsx          # Root component
│   ├── index.css        # Global styles (Tailwind)
│   └── main.tsx         # Entry point
├── .env.example         # Environment template
├── tailwind.config.js   # Tailwind configuration
├── postcss.config.js    # PostCSS configuration
├── vite.config.ts       # Vite configuration
└── package.json         # Dependencies
```

## Component Overview

### Header
- Displays ThreatStream branding
- Shows real-time API health status
- Status indicator (healthy/degraded/unhealthy)

### StatCard
- Reusable card component for displaying key metrics
- Supports loading states and trend indicators
- Icons for visual clarity

### IndicatorCard
- Displays threat indicator summary
- Shows confidence score, type, and severity
- MITRE ATT&CK technique badges
- Source count and timestamp

### IndicatorModal
- Detailed view of a single indicator
- Full enrichment data display
- Source timeline information
- Recommended actions list

### IndicatorTypeChart
- Pie chart visualization of indicator distribution
- Color-coded by indicator type
- Interactive legend and tooltips

### SearchFilters
- Full-text search input
- Indicator type dropdown filter
- Confidence score slider (0-100%)
- Real-time filter application

### RealTimeFeed
- Server-Sent Events (SSE) stream
- Connection status indicator
- Displays last 10 real-time indicators
- Automatic reconnection on errors

## API Integration

The dashboard integrates with the ThreatStream API using a type-safe client (`src/services/api.ts`).

### API Client Methods

```typescript
// Health check
await apiClient.getHealth();

// Query indicators
await apiClient.getIndicators({
  indicator_type: 'domain',
  confidence_min: 80,
  page_size: 50
});

// Search indicators
await apiClient.searchIndicators({
  q: 'malicious.com',
  page_size: 10
});

// Get indicator by ID
await apiClient.getIndicatorById('otx_malicious.com');

// Get relationships
await apiClient.getRelationships('malicious.com');

// Get platform statistics
await apiClient.getStats();

// Create SSE stream
const eventSource = apiClient.createIndicatorStream(
  (indicator) => console.log('New indicator:', indicator),
  (error) => console.error('Stream error:', error),
  { confidence_min: 90 }
);
```

## Styling

### TailwindCSS Utilities

Custom utility classes defined in `src/index.css`:

```css
.card               /* White card with shadow */
.badge              /* Small rounded badge */
.badge-danger       /* Red badge (high/critical) */
.badge-warning      /* Yellow badge (medium) */
.badge-success      /* Green badge (low) */
.badge-info         /* Blue badge (info) */
```

### Dark Mode

The dashboard supports dark mode automatically based on system preferences. All components use dark mode variants:

```tsx
<div className="bg-white dark:bg-gray-800">
  <p className="text-gray-900 dark:text-white">Text</p>
</div>
```

## Deployment

### Static Hosting (Netlify, Vercel, etc.)

1. Build the project:
```bash
npm run build
```

2. Deploy the `dist/` directory to your hosting provider.

3. Set environment variables in your hosting dashboard:
   - `VITE_API_BASE_URL`
   - `VITE_API_KEY`

### Docker

Create a `Dockerfile`:

```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ARG VITE_API_BASE_URL
ARG VITE_API_KEY
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Build and run:

```bash
docker build --build-arg VITE_API_BASE_URL=https://api.example.com --build-arg VITE_API_KEY=your-key -t threatstream-dashboard .
docker run -p 80:80 threatstream-dashboard
```

## Troubleshooting

### Dashboard shows "Connection error" in Live Feed

**Cause**: API is not running or SSE endpoint is unavailable.

**Solution**:
```bash
# Verify API is running
curl http://localhost:8000/health

# Check SSE endpoint
curl -H "X-API-Key: your-key" http://localhost:8000/stream/indicators
```

### "Failed to load data" error on startup

**Cause**: Invalid API key or API not accessible.

**Solution**:
- Verify `VITE_API_KEY` in `.env` is correct
- Check `VITE_API_BASE_URL` points to running API
- Restart dev server after changing `.env`

### Charts not rendering

**Cause**: Missing or invalid statistics data.

**Solution**:
- Ensure API `/stats` endpoint returns valid data
- Check browser console for errors
- Verify data format matches `Stats` type in `src/types/api.ts`

### Dark mode not working

**Cause**: Missing TailwindCSS dark mode configuration.

**Solution**:
- Ensure `tailwind.config.js` has `darkMode: 'media'` or `darkMode: 'class'`
- Check browser console for CSS errors

## Performance Optimization

### Code Splitting

The dashboard uses Vite's automatic code splitting. For manual chunks:

```typescript
// vite.config.ts
export default {
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react': ['react', 'react-dom'],
          'vendor-charts': ['recharts'],
        }
      }
    }
  }
}
```

### Caching Strategy

The API client automatically benefits from browser caching. For production, set appropriate cache headers:

```nginx
# nginx.conf
location /static/ {
  expires 1y;
  add_header Cache-Control "public, immutable";
}
```

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Contributing

This is a portfolio project, but feedback is welcome! Please open an issue for bugs or suggestions.

## License

MIT License - See [LICENSE](../LICENSE) file

---

**Part of the ThreatStream Intelligence Pipeline**
- **Backend API**: [../ingestion/](../ingestion/)
- **Documentation**: [../docs/](../docs/)
- **Main README**: [../README.md](../README.md)
