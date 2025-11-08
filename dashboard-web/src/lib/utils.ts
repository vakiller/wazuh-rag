import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string): string {
  return new Date(date).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatRelativeTime(date: string): string {
  const now = new Date();
  const then = new Date(date);
  const diffInSeconds = Math.floor((now.getTime() - then.getTime()) / 1000);

  if (diffInSeconds < 60) return 'just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
  return `${Math.floor(diffInSeconds / 86400)}d ago`;
}

export function getSeverityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'text-critical bg-critical/10 border-critical/20';
    case 'high':
      return 'text-high bg-high/10 border-high/20';
    case 'medium':
      return 'text-medium bg-medium/10 border-medium/20';
    case 'low':
      return 'text-low bg-low/10 border-low/20';
    default:
      return 'text-gray-400 bg-gray-400/10 border-gray-400/20';
  }
}

export function getRiskScoreColor(score: number): string {
  if (score >= 80) return 'text-critical';
  if (score >= 60) return 'text-high';
  if (score >= 40) return 'text-medium';
  return 'text-low';
}

export function getSeverityIcon(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return '🔴';
    case 'high':
      return '🟠';
    case 'medium':
      return '🟡';
    case 'low':
      return '🟢';
    default:
      return '⚪';
  }
}
