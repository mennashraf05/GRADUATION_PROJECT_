import React, { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Badge } from '../ui/badge';
import { Progress } from '../ui/progress';
import { useLanguage } from '../../contexts/LanguageContext';
import {
  Globe,
  Search,
  Shield,
  AlertTriangle,
  XCircle,
  CheckCircle,
  Clock,
  ExternalLink,
  TrendingUp,
  Eye
} from 'lucide-react';

/* =========================
   Configuration
========================= */
const BASE_API_URL = 'http://localhost:5000';
const SCAN_API_URL = `${BASE_API_URL}/api/v1/scan-url`;
const SCANS_API_URL = `${BASE_API_URL}/api/v1/scans`;

/* =========================
   Types
========================= */
type ScanStatus = 'safe' | 'suspicious' | 'dangerous';

interface ScanResult {
  status: ScanStatus;
  score: number;
  details: string[];
}

interface ScanHistoryItem {
  id: number;
  url: string;
  category: ScanStatus;
  risk_score: number;
  created_at?: string;
}

/* =========================
   Component
========================= */
export function PhishingScannerPage() {
  const { language, isRtl, formatNumber } = useLanguage();
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);

  /* =========================
     Fetch Scan History
  ========================== */
  const fetchScanHistory = async () => {
    try {
      const res = await fetch(SCANS_API_URL, {
        credentials: 'include', // ✅ إضافة الكوكيز
      });
      if (!res.ok) return;
      const data = await res.json();
      setScanHistory(data);
    } catch (err) {
      console.error('Failed to load scan history', err);
    }
  };

  useEffect(() => {
    fetchScanHistory();
  }, []);

  /* =========================
     Handle Scan
  ========================== */
  const handleScan = async () => {
    if (!url) return;

    setIsScanning(true);
    setScanResult(null);

    try {
      const res = await fetch(SCAN_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
        credentials: 'include', // ✅ إضافة الكوكيز
      });

      if (!res.ok) throw new Error('Scan failed');

      const data = await res.json();

      setScanResult({
        status: data.category,
        score: data.risk_score,
        details: [
          `ML Probability: ${(data.ml_result.probability * 100).toFixed(2)}%`,
          language === 'arabic' ? `فئة الخطورة: ${data.category}` : `Risk Category: ${data.category}`,
          language === 'arabic' ? `نطاق موثوق: ${data.ml_result.trusted_domain ? 'نعم' : 'لا'}` : `Trusted Domain: ${data.ml_result.trusted_domain ? 'Yes' : 'No'}`,
          data.guidance
        ]
      });

      fetchScanHistory();
    } catch (err) {
      console.error(err);
      setScanResult({
        status: 'dangerous',
        score: 0,
        details: [language === 'arabic' ? 'تعذر الاتصال بالخادم. حاول مرة أخرى لاحقًا.' : 'Error contacting server. Please try again later.']
      });
    } finally {
      setIsScanning(false);
    }
  };

  /* =========================
     Helpers
  ========================== */
  const getStatusIcon = (status: ScanStatus) => {
    if (status === 'safe') return <CheckCircle className="w-4 h-4 text-green-400" />;
    if (status === 'suspicious') return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
    return <XCircle className="w-4 h-4 text-red-400" />;
  };

  const getStatusBadge = (status: ScanStatus) => {
    if (status === 'safe')
      return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">{language === 'arabic' ? 'آمن' : 'Safe'}</Badge>;
    if (status === 'suspicious')
      return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">{language === 'arabic' ? 'مشبوه' : 'Suspicious'}</Badge>;
    return <Badge className="bg-red-500/20 text-red-400 border-red-500/30">{language === 'arabic' ? 'خطير' : 'Dangerous'}</Badge>;
  };

  const getScoreColor = (score: number) => {
    if (score >= 70) return 'text-green-400';
    if (score >= 40) return 'text-yellow-400';
    return 'text-red-400';
  };

  const totalScans = scanHistory.length;
  const safeCount = scanHistory.filter(s => s.category === 'safe').length;
  const dangerousCount = scanHistory.filter(s => s.category === 'dangerous').length;
  const safePercentage = totalScans ? (safeCount / totalScans) * 100 : 0;

  /* =========================
     Render
  ========================== */
  return (
    <div className="space-y-6" dir={isRtl ? 'rtl' : 'ltr'}>

      {/* Header */}
      <div className="flex items-center space-x-3">
        <div className="w-10 h-10 bg-gradient-to-r from-yellow-500 to-yellow-600 rounded-lg flex items-center justify-center">
          <Globe className="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-white">{language === 'arabic' ? 'فاحص روابط التصيد' : 'Phishing URL Scanner'}</h1>
          <p className="text-gray-400 mt-1">{language === 'arabic' ? 'كشف فوري لروابط التصيد باستخدام التعلم الآلي' : 'Real-time phishing detection using ML'}</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="cyber-card"><CardContent className="p-6">
          <p className="text-gray-400 text-sm">{language === 'arabic' ? 'إجمالي الفحوصات' : 'Total Scans'}</p>
          <p className="text-2xl font-bold text-white">{formatNumber(totalScans)}</p>
        </CardContent></Card>

        <Card className="cyber-card"><CardContent className="p-6">
          <p className="text-gray-400 text-sm">{language === 'arabic' ? 'روابط آمنة' : 'Safe URLs'}</p>
          <p className="text-2xl font-bold text-green-400">{formatNumber(safeCount)}</p>
        </CardContent></Card>

        <Card className="cyber-card"><CardContent className="p-6">
          <p className="text-gray-400 text-sm">{language === 'arabic' ? 'تهديدات مكتشفة' : 'Threats Detected'}</p>
          <p className="text-2xl font-bold text-red-400">{formatNumber(dangerousCount)}</p>
        </CardContent></Card>

        <Card className="cyber-card"><CardContent className="p-6">
          <p className="text-gray-400 text-sm">{language === 'arabic' ? 'معدل الأمان' : 'Safety Rate'}</p>
          <p className="text-2xl font-bold text-purple-400">{safePercentage.toFixed(0)}%</p>
        </CardContent></Card>
      </div>

      {/* Scanner */}
      <Card className="cyber-card">
        <CardHeader>
          <CardTitle className="text-white flex items-center">
            <Search className="w-5 h-5 mr-2 text-blue-400" />
            {language === 'arabic' ? 'فحص الرابط' : 'Scan URL'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <Label className="text-white">{language === 'arabic' ? 'أدخل الرابط' : 'Enter URL'}</Label>
          <div className="flex gap-2">
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="bg-gray-800 text-white"
            />
            <Button onClick={handleScan} disabled={isScanning || !url}>
              {isScanning ? (language === 'arabic' ? 'جارٍ الفحص...' : 'Scanning...') : language === 'arabic' ? 'فحص' : 'Scan'}
            </Button>
          </div>

          {isScanning && <Progress value={65} />}

          {scanResult && (
            <div className="p-5 rounded-lg border border-gray-700">
              <div className="flex justify-between mb-3">
                <div className="flex items-center gap-2">
                  {getStatusIcon(scanResult.status)}
                  {getStatusBadge(scanResult.status)}
                </div>
                <span className={`font-bold ${getScoreColor(scanResult.score)}`}>
                  {scanResult.score}/100
                </span>
              </div>

              {scanResult.details.map((d, i) => (
                <p key={i} className="text-gray-300 text-sm">• {d}</p>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* History */}
      <Card className="cyber-card">
        <CardHeader>
          <CardTitle className="text-white flex items-center">
            <Clock className="w-5 h-5 mr-2" /> {language === 'arabic' ? 'سجل الفحص' : 'Scan History'}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{language === 'arabic' ? 'الرابط' : 'URL'}</TableHead>
                <TableHead>{language === 'arabic' ? 'الحالة' : 'Status'}</TableHead>
                <TableHead>{language === 'arabic' ? 'درجة الخطورة' : 'Risk Score'}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scanHistory.map(scan => (
                <TableRow key={scan.id}>
                  <TableCell className="font-mono text-sm">{scan.url}</TableCell>
                  <TableCell>{getStatusBadge(scan.category)}</TableCell>
                  <TableCell className={getScoreColor(scan.risk_score)}>
                    {scan.risk_score}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

    </div>
  );
}
