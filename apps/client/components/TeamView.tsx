import React, { useCallback, useEffect, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { checkoutChoices, checkoutNotice, limitSummary, openBillingPage } from "../src/billing";
import { confirmAsync } from "../src/dialogs";
import { errorText, friendlyError } from "../src/errors";
import { defaultEnd, endChoices, endNear, endsAt } from "../src/roles";
import {
  appliesLine,
  assignableRoles,
  blockedReason,
  canRemove,
  customRoleActions,
  customRoleLine,
  leaveBlocked,
  looksLikeEmail,
  machineStatus,
  managesTeam,
  offboardingMessage,
  seatsLine,
  TEAM_ROLE_LABEL,
  teamPlanLine,
  TEAM_DECIDES_YOURS,
  teamApproveBlocked,
  teamRegionLine,
  teamSubscriptionLine,
} from "../src/team";
import { hairline, themedStyles, type } from "../src/theme";
import type { CheckoutInterval, CustomRoleRef, MyTeamInvite, RoleRequest, Team, TeamBilling, TeamMember, TeamRole, TeamRoleChoice } from "../src/types";
import { Chips } from "./Chips";
import { EmptyState } from "./EmptyState";
import { ErrorState, InlineError } from "./ErrorState";
import { RequestRow } from "./RolesAdmin";
import { BusyDots, PageSkeleton } from "./Skeleton";
import { kit, PageHeader, usePlaceholder } from "./ui";

interface Props {
  api: SuperBotApi;
  meId?: string | null;
  /** Read-only people see their team and change nothing; the server refuses them anyway. */
  canWrite: boolean;
  onBack: () => void;
  /** `?checkout=` from Stripe's return link, after buying the team's plan. */
  checkout?: string | string[];
  /** Opens a Stripe page; `openBillingPage` unless a test swaps it. */
  open?: (url: string) => Promise<void>;
}

/** After a successful checkout, how often and how many times to look for Stripe's confirmation. */
export const TEAM_CONFIRM_EVERY_MS = 3000;
const CONFIRM_TRIES = 20;

/** Giving a teammate one of the team's custom roles, for how long (ADR 0254). */
function GiveRole({
  choices,
  held,
  busy,
  onGive,
  onCancel,
}: {
  choices: TeamRoleChoice[];
  /** The role they hold now: a change starts on it, and near its end. */
  held?: CustomRoleRef | null;
  busy: boolean;
  onGive: (roleId: string, ends: string) => void;
  onCancel: () => void;
}) {
  const styles = useStyles();
  const [roleId, setRoleId] = useState((choices.find((c) => c.id === held?.id) ?? choices[0]).id);
  const choice = choices.find((c) => c.id === roleId) ?? choices[0];
  const [ends, setEnds] = useState(() => (held && held.id === choice.id ? endNear(choice.maxDays, held.expiresAt, Date.now()) : defaultEnd(choice.maxDays)));
  const pick = (id: string) => {
    setRoleId(id);
    setEnds(defaultEnd(choices.find((c) => c.id === id)?.maxDays));
  };
  return (
    <View style={styles.rolePanel} testID="give-role">
      <Chips options={choices.map((c) => ({ value: c.id, label: c.name }))} value={choice.id} onChange={pick} disabled={busy} />
      {choice.description ? <Text style={styles.dim}>{choice.description}</Text> : null}
      <Text style={styles.faint}>{appliesLine(choice)}</Text>
      <Chips options={endChoices(choice.maxDays)} value={ends} onChange={setEnds} disabled={busy} />
      <View style={styles.actions}>
        <Pressable style={styles.primaryBtn} disabled={busy} onPress={() => onGive(choice.id, ends)} accessibilityRole="button">
          <Text style={styles.primaryText}>Give {choice.name}</Text>
        </Pressable>
        <Pressable style={styles.btn} disabled={busy} onPress={onCancel} accessibilityRole="button" accessibilityLabel="Cancel giving a team role">
          <Text style={styles.btnText}>Cancel</Text>
        </Pressable>
      </View>
    </View>
  );
}

function MemberRow({
  m,
  first,
  team,
  meId,
  manage,
  busy,
  onRole,
  onRemove,
  onGiveRole,
  onTakeRole,
}: {
  m: TeamMember;
  first: boolean;
  team: Team;
  meId?: string | null;
  manage: boolean;
  busy: boolean;
  onRole: (m: TeamMember, role: TeamRole) => void;
  onRemove: (m: TeamMember) => void;
  onGiveRole: (m: TeamMember, roleId: string, ends: string) => void;
  onTakeRole: (m: TeamMember) => void;
}) {
  const styles = useStyles();
  const [giving, setGiving] = useState(false);
  const roles = manage ? assignableRoles(team.role, m) : [];
  const status = manage ? machineStatus(m.machine) : null;
  const custom = manage ? customRoleActions(team, m, meId) : { give: false, take: false };
  const roleLine = customRoleLine(m.customRole);
  const who = m.name ?? m.email ?? m.id;
  return (
    <View style={[styles.member, first && styles.memberFirst]} accessibilityLabel={`Teammate ${m.name ?? m.email ?? m.id}`}>
      <View style={styles.memberHead}>
        <View style={styles.grow}>
          <Text style={styles.name} numberOfLines={1}>
            {m.name ?? m.email ?? m.id}
            {m.id === meId ? <Text style={styles.faint}> · you</Text> : null}
          </Text>
          {m.email ? <Text style={styles.dim} numberOfLines={1}>{m.email}</Text> : null}
        </View>
        <Text style={[styles.tag, m.role !== "member" && styles.roleTag]}>{TEAM_ROLE_LABEL[m.role] ?? m.role}</Text>
        {!m.active ? <Text style={[styles.tag, styles.badTag]}>Disabled</Text> : null}
      </View>
      {status ? (
        <View testID={`machine-${m.id}`}>
          <Text style={[styles.status, styles[status.tone]]}>{status.label}</Text>
          {status.detail ? <Text style={styles.faint}>{status.detail}</Text> : null}
        </View>
      ) : null}
      {roles.length > 1 ? (
        <Chips
          options={roles.map((r) => ({ value: r, label: TEAM_ROLE_LABEL[r] }))}
          value={m.role}
          disabled={busy}
          onChange={(r) => r !== m.role && onRole(m, r)}
        />
      ) : null}
      {roleLine ? (
        <Text style={styles.dim} testID={`custom-role-${m.id}`}>
          Team role: {roleLine}
        </Text>
      ) : null}
      {giving && custom.give ? (
        <GiveRole
          choices={team.roleChoices ?? []}
          held={m.customRole}
          busy={busy}
          onGive={(roleId, ends) => {
            setGiving(false);
            onGiveRole(m, roleId, ends);
          }}
          onCancel={() => setGiving(false)}
        />
      ) : custom.give || custom.take ? (
        <View style={styles.actions}>
          {custom.give ? (
            <Pressable style={styles.btn} disabled={busy} onPress={() => setGiving(true)} accessibilityRole="button" accessibilityLabel={`${m.customRole ? "Change" : "Give"} team role for ${who}`}>
              <Text style={styles.btnText}>{m.customRole ? "Change team role" : "Give a team role"}</Text>
            </Pressable>
          ) : null}
          {custom.take ? (
            <Pressable style={styles.btn} disabled={busy} onPress={() => onTakeRole(m)} accessibilityRole="button" accessibilityLabel={`Take away team role from ${who}`}>
              <Text style={styles.btnText}>Take away role</Text>
            </Pressable>
          ) : null}
        </View>
      ) : null}
      {manage && canRemove(team.role, m, meId) ? (
        <Pressable style={styles.dangerBtn} disabled={busy} onPress={() => onRemove(m)} accessibilityRole="button" accessibilityLabel={`Remove ${m.name ?? m.email ?? m.id}`}>
          <Text style={styles.dangerText}>Remove from team</Text>
        </Pressable>
      ) : null}
    </View>
  );
}

/** The team's plan (ADR 0093): who pays for everyone's, and for owners and admins, its seats and Stripe's pages. */
function TeamPlan({ b, manage, busy, onBuy, onPortal }: { b: TeamBilling; manage: boolean; busy: boolean; onBuy: (tier: string, interval?: CheckoutInterval) => void; onPortal: () => void }) {
  const styles = useStyles();
  const status = teamSubscriptionLine(b);
  const seats = seatsLine(b);
  const change = manage && b.canChange !== false;
  return (
    <View style={styles.section} testID="team-plan">
      <Text style={styles.sectionTitle} role="heading">
        Plan
      </Text>
      <View style={styles.card}>
        <Text style={styles.name} role="heading">
          {b.plan ? `${b.plan.label} plan` : "No team plan"}
        </Text>
        <Text style={styles.dim}>{teamPlanLine(b)}</Text>
        {status ? <Text style={styles.dim}>{status}</Text> : null}
        {seats ? <Text style={[styles.status, styles[seats.tone]]}>{seats.text}</Text> : null}
        {change && b.portal ? (
          <Pressable style={[styles.btn, styles.self]} disabled={busy} onPress={onPortal} accessibilityRole="link" accessibilityHint="Opens Stripe's billing page">
            <Text style={styles.btnText}>Manage billing</Text>
          </Pressable>
        ) : null}
      </View>
      {change && !b.plan
        ? b.plans?.map((p) => (
            <View key={p.name} style={styles.card}>
              <Text style={styles.name} role="heading">
                {p.label}
              </Text>
              <Text style={styles.faint}>{limitSummary(p.limits).join(" · ")}</Text>
              {checkoutChoices(p.intervals).map(({ interval, suffix }) => (
                <Pressable
                  key={interval ?? "default"}
                  style={[styles.primaryBtn, styles.self]}
                  disabled={busy}
                  onPress={() => onBuy(p.name, interval)}
                  accessibilityRole="link"
                  accessibilityLabel={`Buy ${p.label} for the team${suffix}`}
                  accessibilityHint="Opens Stripe Checkout to pay"
                >
                  <Text style={styles.primaryText}>
                    Buy {p.label} for the team{suffix}
                  </Text>
                </Pressable>
              ))}
            </View>
          ))
        : null}
      {change && !b.plan && b.plans?.length ? <Text style={styles.faint}>A seat for each person on the team. Everyone gets the plan's limits and machine size.</Text> : null}
      {!manage && b.plan ? <Text style={styles.faint}>Only the team's owners and admins can change the team's plan.</Text> : null}
    </View>
  );
}

/** Your team (ADR 0087, 0088): its people and, for owners and admins, their machines, invites, roles and offboarding. */
export function TeamView({ api, meId, canWrite, onBack, checkout, open = openBillingPage }: Props) {
  const styles = useStyles();
  const placeholder = usePlaceholder();
  const [team, setTeam] = useState<Team | null | undefined>(undefined);
  const [invites, setInvites] = useState<MyTeamInvite[]>([]);
  const [error, setError] = useState<string | null>(null);
  /** The team didn't load: alone it fills the screen, after a refresh it sits above what's already shown. */
  const [loadError, setLoadError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Exclude<TeamRole, "owner">>("member");

  const [requests, setRequests] = useState<RoleRequest[]>([]);
  const [requestsError, setRequestsError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [t, i] = await Promise.all([api.team(), api.myTeamInvites()]);
      setTeam(t);
      setInvites(i);
      // Only owners and admins get a count, so nobody else asks (nor an older server, without one).
      let waiting: RoleRequest[] = [];
      let failed: string | null = null;
      if (t?.roleRequests) {
        try {
          waiting = (await api.teamRoleRequests("pending")).requests;
        } catch (e) {
          failed = errorText(e, "Couldn't load requests for team roles");
        }
      }
      setRequests(waiting);
      setRequestsError(failed);
      setLoadError(null);
    } catch (e) {
      setLoadError(e);
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const notice = checkoutNotice(checkout, true);
  // Stripe can send people back before its webhook reaches the server: keep looking for a minute.
  const waiting = notice?.good === true && !!team?.billing && !team.billing.plan;
  useEffect(() => {
    if (!waiting) return;
    let tries = 0;
    const timer = setInterval(() => {
      if (++tries >= CONFIRM_TRIES) clearInterval(timer);
      void load();
    }, TEAM_CONFIRM_EVERY_MS);
    return () => clearInterval(timer);
  }, [waiting, load]);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(friendlyError(e, "That didn't work. Try again."));
    } finally {
      setBusy(false);
      await load();
    }
  };

  const manage = !!team && managesTeam(team.role) && canWrite;

  const changeRole = (m: TeamMember, to: TeamRole) =>
    run(async () => {
      const who = m.name ?? m.email ?? "them";
      if (to === "owner" && !(await confirmAsync(`Make ${who} an owner?`, "Owners can make and remove other owners, and take anyone off the team.", "Make owner"))) return;
      if (m.id === meId && !(await confirmAsync("Change your own role?", `You'll be ${TEAM_ROLE_LABEL[to].toLowerCase()} and may not be able to change it back.`, "Change"))) return;
      await api.setTeamRole(m.id, to);
    });

  const giveRole = (m: TeamMember, roleId: string, ends: string) => run(() => api.giveTeamCustomRole(m.id, roleId, { expiresAt: endsAt(ends, Date.now()) }));

  const takeRole = (m: TeamMember) =>
    run(async () => {
      const who = m.name ?? m.email ?? "them";
      if (!(await confirmAsync(`Take ${m.customRole?.name ?? "their role"} away from ${who}?`, "They keep their place on the team, and lose what the role let them do in it.", "Take away"))) return;
      await api.takeTeamCustomRole(m.id);
    });

  const remove = (m: TeamMember) =>
    run(async () => {
      const p = await api.offboardingPreview(m.id);
      const why = blockedReason(p);
      if (!p.allowed) throw new Error(why ?? "You can't take them off the team.");
      if (!(await confirmAsync(`Remove ${p.user.name ?? m.email ?? "them"} from ${team?.name ?? "the team"}?`, offboardingMessage(p, team?.name ?? "the team"), "Remove"))) return;
      await api.removeTeammate(m.id);
    });

  const pay = (start: () => Promise<{ url: string }>) => run(async () => open((await start()).url));

  const invite = () =>
    run(async () => {
      if (!looksLikeEmail(email)) throw new Error("Enter their email address.");
      await api.inviteToTeam(email.trim(), role);
      setEmail("");
    });

  const leave = () =>
    run(async () => {
      const msg = "You lose access to teammates' shared Bots and they lose access to yours. A machine the team gave you is suspended, then deleted unless you join a team again.";
      if (!(await confirmAsync(`Leave ${team?.name ?? "the team"}?`, msg, "Leave"))) return;
      await api.leaveTeam();
    });

  const accept = (i: MyTeamInvite) =>
    run(async () => {
      const msg = "Joining shares Bots with this team only: you lose access to shared Bots of people outside it, and they to yours.";
      if (!(await confirmAsync(`Join ${i.team.name ?? "this team"}?`, msg, "Join"))) return;
      await api.acceptTeamInvite(i.id);
    });

  return (
    <View style={styles.root}>
      <PageHeader title={team ? team.name : "Team"} onBack={onBack} right={busy ? <BusyDots label="Saving" /> : null} />
      <ScrollView contentContainerStyle={styles.body}>
        {notice ? (
          <Text style={[styles.status, notice.good ? styles.ok : styles.dim]} accessibilityRole="alert">
            {notice.text}
          </Text>
        ) : null}
        {team !== undefined && loadError ? <InlineError message={errorText(loadError, "Couldn't refresh your team")} onRetry={load} /> : null}
        {error ? <InlineError message={error} /> : null}
        {team === undefined ? (
          loadError ? (
            <ErrorState title="Couldn't load your team" message={friendlyError(loadError)} onRetry={load} />
          ) : (
            <PageSkeleton label="Loading your team" inset={false} />
          )
        ) : null}

        {team === null ? (
          <EmptyState
            compact
            glyph="+"
            title="You aren't on a team"
            message={
              invites.length && canWrite
                ? "Join a team from one of your invites below."
                : "Ask a team's owner or admin to invite you with the email you sign in with."
            }
          />
        ) : null}
        {team === null && invites.length ? (
          <View style={styles.section}>
            <Text style={styles.sectionTitle} role="heading">
              Invites for you
            </Text>
            {invites.map((i) => (
              <View key={i.id} style={styles.card} accessibilityLabel={`Invite to ${i.team.name ?? i.team.id}`}>
                <Text style={styles.name} role="heading">
                  {i.team.name ?? i.team.id}
                </Text>
                <Text style={styles.dim}>
                  As {TEAM_ROLE_LABEL[i.role].toLowerCase()} · until {new Date(i.expiresAt).toLocaleDateString()}
                </Text>
                {canWrite ? (
                  <View style={styles.actions}>
                    <Pressable style={styles.primaryBtn} disabled={busy} onPress={() => accept(i)} accessibilityRole="button" accessibilityLabel={`Join ${i.team.name ?? i.team.id}`}>
                      <Text style={styles.primaryText}>Join</Text>
                    </Pressable>
                    <Pressable
                      style={styles.btn}
                      disabled={busy}
                      onPress={() => run(() => api.declineTeamInvite(i.id))}
                      accessibilityRole="button"
                      accessibilityLabel={`Decline invite to ${i.team.name ?? i.team.id}`}
                    >
                      <Text style={styles.btnText}>Decline</Text>
                    </Pressable>
                  </View>
                ) : null}
              </View>
            ))}
          </View>
        ) : null}

        {team ? (
          <>
            <Text style={styles.dim}>
              You're {team.role ? `${TEAM_ROLE_LABEL[team.role].toLowerCase()}` : "on this team"} · {team.members.length} {team.members.length === 1 ? "person" : "people"}
            </Text>
            {teamRegionLine(team) ? <Text style={styles.dim}>{teamRegionLine(team)}</Text> : null}
            {!manage ? <Text style={styles.faint}>Only the team's owners and admins can change the team.</Text> : null}

            {team.billing ? (
              <TeamPlan b={team.billing} manage={manage} busy={busy} onBuy={(tier, interval) => pay(() => (interval ? api.teamCheckout(tier, interval) : api.teamCheckout(tier)))} onPortal={() => pay(() => api.teamBillingPortal())} />
            ) : null}

            {manage ? (
              <View style={styles.section}>
                <Text style={styles.sectionTitle} role="heading">
                  Invite a teammate
                </Text>
                <View style={styles.card}>
                  <Text style={styles.faint}>They join when they accept, signed in with this email.{team.machines ? " Joining gives them a machine of their own." : ""}</Text>
                  <TextInput
                    style={styles.input}
                    value={email}
                    onChangeText={setEmail}
                    placeholder="name@example.com"
                    placeholderTextColor={placeholder}
                    autoCapitalize="none"
                    autoCorrect={false}
                    keyboardType="email-address"
                    accessibilityLabel="Teammate's email"
                  />
                  <Chips
                    options={[
                      { value: "member" as const, label: "Member" },
                      { value: "admin" as const, label: "Admin" },
                    ]}
                    value={role}
                    onChange={setRole}
                    disabled={busy}
                  />
                  <Pressable style={[styles.primaryBtn, styles.self]} disabled={busy} onPress={invite} accessibilityRole="button">
                    <Text style={styles.primaryText}>Send invite</Text>
                  </Pressable>
                  {team.invites?.length ? (
                    <View style={styles.invites} testID="team-invites">
                      {team.invites.map((i) => (
                        <View key={i.id} style={styles.inviteRow}>
                          <Text style={[styles.dim, styles.grow]} numberOfLines={1}>
                            {i.email} · {TEAM_ROLE_LABEL[i.role]} · until {new Date(i.expiresAt).toLocaleDateString()}
                          </Text>
                          <Pressable disabled={busy} onPress={() => run(() => api.cancelTeamInvite(i.id))} accessibilityRole="button" accessibilityLabel={`Cancel invite for ${i.email}`}>
                            <Text style={styles.link}>Cancel</Text>
                          </Pressable>
                        </View>
                      ))}
                    </View>
                  ) : null}
                </View>
              </View>
            ) : null}

            {manage && requestsError ? (
              <View style={styles.section}>
                <InlineError message={requestsError} onRetry={load} retryLabel="Load requests again" />
              </View>
            ) : null}
            {manage && requests.length ? (
              <View style={styles.section} testID="team-role-requests">
                <Text style={styles.sectionTitle} role="heading">
                  Requests for team roles ({requests.length})
                </Text>
                <Text style={styles.faint}>Approving gives the role in this team only, for the hours asked or fewer, and it ends by itself.</Text>
                {requests.map((q) => (
                  <RequestRow
                    key={q.id}
                    q={q}
                    meId={meId}
                    onDecided={load}
                    approve={(id, body) => api.approveTeamRoleRequest(id, body)}
                    deny={(id, note) => api.denyTeamRoleRequest(id, note)}
                    decidesYours={TEAM_DECIDES_YOURS}
                    approveBlocked={teamApproveBlocked(team, q)}
                  />
                ))}
              </View>
            ) : null}

            <View style={styles.section}>
              <Text style={styles.sectionTitle} role="heading">
                People
              </Text>
              <View style={styles.list}>
                {team.members.length ? (
                  team.members.map((m, i) => (
                    <MemberRow key={m.id} m={m} first={i === 0} team={team} meId={meId} manage={manage} busy={busy} onRole={changeRole} onRemove={remove} onGiveRole={giveRole} onTakeRole={takeRole} />
                  ))
                ) : (
                  <EmptyState compact glyph="+" title="No one on the team yet" message={manage ? "Invite a teammate above." : "People show here once they join."} />
                )}
              </View>
            </View>

            {canWrite ? (
              <View style={styles.section}>
                {leaveBlocked(team) === null ? (
                  <Pressable style={[styles.dangerBtn, styles.self]} disabled={busy} onPress={leave} accessibilityRole="button">
                    <Text style={styles.dangerText}>Leave team</Text>
                  </Pressable>
                ) : (
                  <Text style={styles.faint}>{leaveBlocked(team)}</Text>
                )}
              </View>
            ) : null}
          </>
        ) : null}
      </ScrollView>
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    body: k.body,
    section: { gap: t.space.sm },
    sectionTitle: { ...k.section, marginTop: t.space.sm, marginBottom: 0 },
    list: { ...k.card, gap: 0, paddingVertical: t.space.xs },
    member: { gap: t.space.sm, paddingVertical: t.space.md, borderTopWidth: hairline, borderTopColor: t.c.border },
    memberFirst: { borderTopWidth: 0 },
    memberHead: { flexDirection: "row", alignItems: "center", gap: t.space.sm },
    grow: { flex: 1, minWidth: 0 },
    card: { ...k.card, gap: t.space.sm },
    name: k.strong,
    dim: k.dim,
    faint: k.faint,
    status: { ...type(t, "sm"), fontWeight: t.font.weight.medium },
    ok: { color: t.c.success },
    warn: { color: t.c.warning },
    bad: { color: t.c.danger },
    tag: k.tag,
    roleTag: k.tagAccent,
    badTag: k.tagDanger,
    input: k.input,
    actions: k.actions,
    self: { alignSelf: "flex-start" },
    primaryBtn: { ...k.btn, ...k.primary },
    primaryText: { ...k.btnText, ...k.primaryText },
    btn: k.btn,
    btnText: k.btnText,
    dangerBtn: { ...k.btn, ...k.danger, alignSelf: "flex-start" },
    dangerText: { ...k.btnText, ...k.dangerText },
    invites: { gap: 0 },
    inviteRow: k.row,
    rolePanel: { ...k.inset, marginTop: t.space.xs },
    link: { ...k.link, ...type(t, "sm") },
  });
});
