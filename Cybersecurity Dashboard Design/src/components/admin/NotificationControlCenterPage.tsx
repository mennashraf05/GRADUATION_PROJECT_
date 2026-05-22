import React, { useEffect, useState } from "react";
import {
  AlertTriangle,
  Bell,
  Edit,
  Mail,
  Pause,
  Plus,
  Radar,
  RefreshCw,
  Save,
  Send,
  SlidersHorizontal,
  TestTube2,
  Users,
} from "lucide-react";
import { toast } from "sonner@2.0.3";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card } from "../ui/card";
import { Checkbox } from "../ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Switch } from "../ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import {
  DeliveryStatus,
  NotificationChannel,
  NotificationChannelConfig,
  NotificationHistoryItem,
  NotificationRecipient,
  NotificationSeverity,
  NotificationsSummary,
  getNotificationChannels,
  getNotificationHistory,
  getNotificationRecipients,
  getNotificationsSummary,
  addNotificationRecipient,
  clearNotificationHistory,
  refreshNotificationControlCenter,
  sendTestNotification,
  updateNotificationChannel,
  updateNotificationRecipient,
} from "../../services/adminNotificationsService";
import "./NotificationControlCenterPage.css";

const EMPTY_SUMMARY: NotificationsSummary = {
  activeRecipients: 0,
  enabledChannels: 0,
  criticalRoutes: 0,
  failedDeliveries: 0,
};

type RecipientEditForm = Pick<
  NotificationRecipient,
  "name" | "role" | "email" | "telegramChatId" | "status" | "preferredChannels"
>;

const channelIcon = {
  Email: Mail,
  Telegram: Send,
} satisfies Record<NotificationChannel, typeof Mail>;

function severityClass(severity: NotificationSeverity): string {
  return `notify-badge notify-severity-${severity.toLowerCase()}`;
}

function deliveryClass(status: DeliveryStatus): string {
  return `notify-badge notify-delivery-${status.toLowerCase()}`;
}

function channelClass(channel: NotificationChannel): string {
  return `notify-channel-pill notify-channel-${channel.toLowerCase()}`;
}

function MetricCard({
  title,
  value,
  helper,
  status,
  icon: Icon,
  tone,
}: {
  title: string;
  value: number;
  helper: string;
  status: string;
  icon: typeof Bell;
  tone: "blue" | "purple" | "cyan" | "red";
}) {
  return (
    <Card className="notify-metric-card">
      <div className="notify-metric-content">
        <div>
          <p>{title}</p>
          <strong>{value}</strong>
          <span>{helper}</span>
        </div>
        <div className={`notify-metric-icon notify-metric-${tone}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <Badge className={`notify-status-pill notify-status-${tone}`}>{status}</Badge>
    </Card>
  );
}

function ChannelCard({
  channel,
  onToggle,
  onTest,
}: {
  channel: NotificationChannelConfig;
  onToggle: (enabled: boolean) => void;
  onTest: () => void;
}) {
  const Icon = channel.id === "email" ? Mail : Send;
  return (
    <Card className="notify-channel-card">
      <div className="notify-channel-top">
        <div className={`notify-channel-icon notify-channel-icon-${channel.id}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <h3>{channel.name}</h3>
          <p>{channel.enabled ? "Enabled" : "Disabled"}</p>
        </div>
        <Switch checked={channel.enabled} onCheckedChange={onToggle} />
      </div>
      <p className="notify-channel-description">{channel.description}</p>
        <div className="notify-channel-meta">
        <span>
          Status:
          <b className={channel.status === "failed" ? "text-red-300" : channel.connected ? "text-emerald-300" : "text-amber-300"}>
            {channel.status === "failed" ? " Failed" : channel.connected ? " Connected" : " Not configured"}
          </b>
        </span>
        <span>
          Provider: <b>{channel.provider}</b>
        </span>
        <span>
          Last test: <b>{channel.lastTestSent}</b>
        </span>
      </div>
      <Button variant="outline" className="notify-outline-button" onClick={onTest} disabled={!channel.enabled || !channel.connected}>
        Test Channel
      </Button>
    </Card>
  );
}

export default function NotificationControlCenterPage() {
  const [summary, setSummary] = useState<NotificationsSummary>(EMPTY_SUMMARY);
  const [recipients, setRecipients] = useState<NotificationRecipient[]>([]);
  const [channels, setChannels] = useState<NotificationChannelConfig[]>([]);
  const [history, setHistory] = useState<NotificationHistoryItem[]>([]);
  const [editingRecipientId, setEditingRecipientId] = useState<string | null>(null);
  const [recipientForm, setRecipientForm] = useState<RecipientEditForm | null>(null);
  const [loading, setLoading] = useState(true);
  const loadPage = async (showToast = false) => {
    setLoading(true);
    try {
      await refreshNotificationControlCenter();
      const [summaryResult, recipientsResult, channelsResult, historyResult] =
        await Promise.all([
          getNotificationsSummary(),
          getNotificationRecipients(),
          getNotificationChannels(),
          getNotificationHistory(),
        ]);
      setSummary(summaryResult);
      setRecipients(recipientsResult);
      setChannels(channelsResult);
      setHistory(historyResult);
      if (showToast) toast.success("Notification controls refreshed");
    } catch {
      toast.error("Notification controls could not be loaded.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadPage();
  }, []);

  const runTestNotification = async (override?: {
    recipientId?: string;
    channel?: NotificationChannel;
    severity?: NotificationSeverity;
  }) => {
    try {
      const recipientId = override?.recipientId || recipients.find((recipient) => recipient.status === "Active")?.id || "";
      const channel = override?.channel || "Email";
      const severity = override?.severity || "Critical";
      const result = await sendTestNotification({
        recipientId,
        channel,
        severity,
      });
      setHistory(result.history);
      setChannels(result.channels);
      setSummary(await getNotificationsSummary());
      if (result.status === "Success") {
        toast.success(result.message);
      } else {
        toast.error(result.message);
      }
    } catch {
      setTestState("Failed");
      toast.error("Test notification failed safely. No real message was sent.");
    }
  };

  const toggleRecipient = async (recipientId: string) => {
    const recipient = recipients.find((item) => item.id === recipientId);
    if (!recipient) return;

    const nextStatus = recipient.status === "Active" ? "Paused" : "Active";
    try {
      const nextRecipients = await updateNotificationRecipient(recipientId, { status: nextStatus });
      setRecipients(nextRecipients);
      setSummary(await getNotificationsSummary());
      toast.success(`${recipient.name} is now ${nextStatus.toLowerCase()}.`);
    } catch {
      toast.error("Recipient status could not be updated.");
    }
  };

  const addRecipient = async () => {
    try {
      const nextRecipients = await addNotificationRecipient();
      setRecipients(nextRecipients);
      setSummary(await getNotificationsSummary());
      toast.success("Recipient added. Edit the generated row with the final responder details.");
    } catch {
      toast.error("Recipient could not be added.");
    }
  };

  const openRecipientEditor = (recipient: NotificationRecipient) => {
    setEditingRecipientId(recipient.id);
    setRecipientForm({
      name: recipient.name,
      role: recipient.role,
      email: recipient.email,
      telegramChatId: recipient.telegramChatId,
      status: recipient.status,
      preferredChannels: [...recipient.preferredChannels],
    });
  };

  const closeRecipientEditor = () => {
    setEditingRecipientId(null);
    setRecipientForm(null);
  };

  const updateRecipientForm = <K extends keyof RecipientEditForm>(key: K, value: RecipientEditForm[K]) => {
    setRecipientForm((current) => current ? { ...current, [key]: value } : current);
  };

  const togglePreferredChannel = (channel: NotificationChannel, checked: boolean) => {
    setRecipientForm((current) => {
      if (!current) return current;
      const preferredChannels = checked
        ? Array.from(new Set([...current.preferredChannels, channel]))
        : current.preferredChannels.filter((item) => item !== channel);
      return { ...current, preferredChannels };
    });
  };

  const saveRecipientEdit = async () => {
    if (!editingRecipientId || !recipientForm) return;

    const name = recipientForm.name.trim();
    const role = recipientForm.role.trim();
    const email = recipientForm.email.trim();
    const telegramChatId = recipientForm.telegramChatId.trim();

    if (!name) {
      toast.error("Recipient name is required.");
      return;
    }

    if (!email && !telegramChatId) {
      toast.error("Add an email or Telegram Chat ID before saving.");
      return;
    }

    if (recipientForm.preferredChannels.length === 0) {
      toast.error("Choose at least one preferred channel.");
      return;
    }

    try {
      const nextRecipients = await updateNotificationRecipient(editingRecipientId, {
        ...recipientForm,
        name,
        role: role || "Responder",
        email,
        telegramChatId,
      });
      setRecipients(nextRecipients);
      setSummary(await getNotificationsSummary());
      closeRecipientEditor();
      toast.success("Recipient details updated.");
    } catch {
      toast.error("Recipient details could not be updated.");
    }
  };

  const toggleChannel = async (channelId: NotificationChannelConfig["id"], enabled: boolean) => {
    try {
      const nextChannels = await updateNotificationChannel(channelId, enabled);
      setChannels(nextChannels);
      setSummary(await getNotificationsSummary());
      toast.success(`Channel ${enabled ? "enabled" : "disabled"}.`);
    } catch {
      toast.error("Channel could not be updated.");
    }
  };

  const clearHistory = async () => {
    try {
      const nextHistory = await clearNotificationHistory();
      setHistory(nextHistory);
      setSummary(await getNotificationsSummary());
      toast.success("Delivery history cleared.");
    } catch {
      toast.error("Delivery history could not be cleared.");
    }
  };

  return (
    <section className="notify-shell">
      <div className="notify-grid-bg" />
      <div className="notify-glow notify-glow-a" />
      <div className="notify-glow notify-glow-b" />

      <header className="notify-hero">
        <div className="notify-hero-copy">
          <div className="notify-radar">
            <Radar className="h-5 w-5" />
          </div>
          <div>
            <div className="notify-eyebrow">
              <Bell className="h-4 w-4" />
              Active response routing
            </div>
            <h1>Notification Control Center</h1>
            <p>
              Manage who receives security alerts, how notifications are delivered,
              and when critical events should trigger active response.
            </p>
          </div>
        </div>
        <div className="notify-hero-actions">
          <Button variant="outline" className="notify-outline-button" onClick={() => void loadPage(true)}>
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </header>

      <div className="notify-metric-grid">
        <MetricCard title="Active Recipients" value={summary.activeRecipients} helper="Users receiving alerts" status="+8%" icon={Users} tone="blue" />
        <MetricCard title="Enabled Channels" value={summary.enabledChannels} helper="Out of 2 configured" status="All good" icon={Send} tone="purple" />
        <MetricCard title="Delivery History" value={history.length} helper="Control center test sends" status="Live" icon={Bell} tone="cyan" />
        <MetricCard title="Failed Deliveries" value={summary.failedDeliveries} helper="Last 24 hours" status="Needs review" icon={AlertTriangle} tone="red" />
      </div>

      <div className="notify-workspace">
        <main className="notify-main-column">
          <Card className="notify-panel">
            <div className="notify-panel-head">
              <div>
                <h2>Notification Recipients</h2>
                <p>Administrators and responders who can receive alert notifications.</p>
              </div>
              <Button className="notify-primary-button" onClick={addRecipient}>
                <Plus className="h-4 w-4" />
                Add Recipient
              </Button>
            </div>
            <div className="notify-table-wrap">
              <Table className="min-w-[980px] table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[150px]">Name</TableHead>
                    <TableHead className="w-[110px]">Role</TableHead>
                    <TableHead className="w-[210px]">Email</TableHead>
                    <TableHead className="w-[170px]">Telegram Chat ID</TableHead>
                    <TableHead className="w-[100px]">Status</TableHead>
                    <TableHead className="w-[160px]">Preferred Channels</TableHead>
                    <TableHead className="w-[130px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recipients.map((recipient) => (
                    <TableRow key={recipient.id}>
                      <TableCell className="font-medium text-white">{recipient.name}</TableCell>
                      <TableCell>{recipient.role}</TableCell>
                      <TableCell className="break-all text-slate-300">{recipient.email}</TableCell>
                      <TableCell>{recipient.telegramChatId}</TableCell>
                      <TableCell>
                        <Badge className={recipient.status === "Active" ? "notify-badge notify-delivery-sent" : "notify-badge notify-delivery-skipped"}>
                          {recipient.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="notify-channel-row">
                          {recipient.preferredChannels.map((channel) => {
                            const Icon = channelIcon[channel];
                            return (
                              <span key={channel} className={channelClass(channel)}>
                                <Icon className="h-3.5 w-3.5" />
                              </span>
                            );
                          })}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="notify-action-row">
                          <Button size="sm" variant="outline" title="Edit" onClick={() => openRecipientEditor(recipient)}>
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button size="sm" variant="outline" title="Pause" onClick={() => void toggleRecipient(recipient.id)}>
                            <Pause className="h-4 w-4" />
                          </Button>
                          <Button size="sm" variant="outline" title="Test" onClick={() => {
                            void runTestNotification({ recipientId: recipient.id });
                          }}>
                            <TestTube2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Card>

          <Card className="notify-panel">
            <div className="notify-panel-head">
              <div>
                <h2>Notification Delivery History</h2>
                <p>Recent delivery attempts across alert routes and response channels.</p>
              </div>
              <Button variant="outline" className="notify-outline-button" onClick={clearHistory}>Clear History</Button>
            </div>
            <div className="notify-table-wrap">
              <Table className="min-w-[980px] table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[230px]">Alert Name</TableHead>
                    <TableHead className="w-[170px]">Recipient</TableHead>
                    <TableHead className="w-[110px]">Channel</TableHead>
                    <TableHead className="w-[110px]">Severity</TableHead>
                    <TableHead className="w-[140px]">Delivery Status</TableHead>
                    <TableHead className="w-[190px]">Time</TableHead>
                    <TableHead className="w-[190px]">Failure Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {history.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell className="font-medium text-white">{item.alertName}</TableCell>
                      <TableCell>{item.recipient}</TableCell>
                      <TableCell>{item.channel}</TableCell>
                      <TableCell><span className={severityClass(item.severity)}>{item.severity}</span></TableCell>
                      <TableCell><span className={deliveryClass(item.deliveryStatus)}>{item.deliveryStatus}</span></TableCell>
                      <TableCell className="text-slate-400">{item.time}</TableCell>
                      <TableCell className="text-slate-400">{item.failureReason}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Card>
        </main>

        <aside className="notify-side-column">
          <Card className="notify-panel">
            <div className="notify-panel-head compact">
              <div><h2>Alert Channels</h2><p>Connected delivery services.</p></div>
              <SlidersHorizontal className="h-5 w-5 text-blue-300" />
            </div>
            <div className="notify-channel-stack">
              {channels.map((channel) => (
                <ChannelCard
                  key={channel.id}
                  channel={channel}
                  onToggle={(enabled) => void toggleChannel(channel.id, enabled)}
                  onTest={() => {
                    const selectedChannel = channel.id === "email" ? "Email" : "Telegram";
                    void runTestNotification({ channel: selectedChannel });
                  }}
                />
              ))}
            </div>
          </Card>

        </aside>
      </div>

      <Dialog open={Boolean(editingRecipientId)} onOpenChange={(open) => {
        if (!open) closeRecipientEditor();
      }}>
        <DialogContent
          overlayClassName="notify-edit-overlay"
          className="notify-edit-dialog border-slate-700/80 bg-[#050914] text-white"
        >
          <DialogHeader>
            <DialogTitle>Edit notification recipient</DialogTitle>
            <DialogDescription className="text-slate-400">
              Update the responder details used by notification tests and routing controls.
            </DialogDescription>
          </DialogHeader>

          {recipientForm && (
            <div className="notify-edit-form">
              <div className="notify-edit-field">
                <Label htmlFor="recipient-name">Name</Label>
                <Input
                  id="recipient-name"
                  value={recipientForm.name}
                  onChange={(event) => updateRecipientForm("name", event.target.value)}
                />
              </div>
              <div className="notify-edit-field">
                <Label htmlFor="recipient-role">Role</Label>
                <Input
                  id="recipient-role"
                  value={recipientForm.role}
                  onChange={(event) => updateRecipientForm("role", event.target.value)}
                />
              </div>
              <div className="notify-edit-field">
                <Label htmlFor="recipient-email">Email</Label>
                <Input
                  id="recipient-email"
                  type="email"
                  value={recipientForm.email}
                  onChange={(event) => updateRecipientForm("email", event.target.value)}
                />
              </div>
              <div className="notify-edit-field">
                <Label htmlFor="recipient-telegram">Telegram Chat ID</Label>
                <Input
                  id="recipient-telegram"
                  value={recipientForm.telegramChatId}
                  onChange={(event) => updateRecipientForm("telegramChatId", event.target.value)}
                />
              </div>
              <div className="notify-edit-field">
                <Label>Preferred Channels</Label>
                <div className="notify-edit-checks">
                  {(["Email", "Telegram"] as NotificationChannel[]).map((channel) => (
                    <Label key={channel} className="notify-edit-check">
                      <Checkbox
                        checked={recipientForm.preferredChannels.includes(channel)}
                        onCheckedChange={(checked) => togglePreferredChannel(channel, checked === true)}
                      />
                      {channel}
                    </Label>
                  ))}
                </div>
              </div>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" className="notify-outline-button" onClick={closeRecipientEditor}>
              Cancel
            </Button>
            <Button className="notify-primary-button" onClick={() => void saveRecipientEdit()}>
              <Save className="h-4 w-4" />
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}
