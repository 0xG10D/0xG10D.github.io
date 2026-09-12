const monthIndex: Record<string, number> = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11
};

export function parseAchievementDate(value: string): Date {
  const monthMatch = value.match(/([A-Za-z]{3,})\s+(\d{4})/);
  if (monthMatch) {
    const month = monthIndex[monthMatch[1].slice(0, 3).toLowerCase()] ?? 0;
    return new Date(Number(monthMatch[2]), month, 1);
  }
  const yearMatch = value.match(/(\d{4})/);
  return new Date(yearMatch ? Number(yearMatch[1]) : 0, 0, 1);
}

export function formatAchievementYear(date: Date) {
  return date.getFullYear() > 0 ? String(date.getFullYear()) : 'TBD';
}
