import { Activity, Shield } from 'lucide-react';

interface HeaderProps {
  health?: 'healthy' | 'degraded' | 'unhealthy';
}

export default function Header({ health = 'healthy' }: HeaderProps) {
  const healthColors = {
    healthy: 'bg-green-500',
    degraded: 'bg-yellow-500',
    unhealthy: 'bg-red-500',
  };

  return (
    <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo and Title */}
          <div className="flex items-center space-x-3">
            <div className="flex items-center justify-center w-10 h-10 bg-primary-600 rounded-lg">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">
                ThreatStream
              </h1>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Intelligence Pipeline Dashboard
              </p>
            </div>
          </div>

          {/* Health Status */}
          <div className="flex items-center space-x-2">
            <Activity className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <span className="text-sm text-gray-700 dark:text-gray-300">
              Status:
            </span>
            <div className="flex items-center space-x-2">
              <div className={`w-2 h-2 rounded-full ${healthColors[health]}`} />
              <span className="text-sm font-medium capitalize text-gray-900 dark:text-white">
                {health}
              </span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
