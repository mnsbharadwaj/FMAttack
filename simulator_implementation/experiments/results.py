"""
experiments/results.py - FMAttack Results Formatter

Produces publication-quality ASCII tables and message sequence diagrams
matching the paper's TABLE I (gap analysis) and TABLE II (attack results).

Functions:
    format_table(results_dict)         → TABLE II ASCII table
    format_gap_analysis()              → TABLE I ASCII gap/attack matrix
    format_message_sequence(atk_name)  → ASCII message sequence diagram
"""

from __future__ import annotations

from typing import Any, Dict


# ---------------------------------------------------------------------------
# TABLE II: Attack experiment results
# ---------------------------------------------------------------------------

def format_table(results_dict: Dict[str, Dict[str, Any]]) -> str:
    """
    Format Monte Carlo experiment results as a TABLE II ASCII table.

    Args:
        results_dict: Dict keyed by attack name strings:
            'ATK-1 VPPB-REBIND', 'ATK-2 PORTDOS',
            'ATK-3 DCDRAIN',     'ATK-4 TUNNELSPOOF'
            Each value is the dict returned by run_attack_montecarlo().

    Returns:
        Multi-line ASCII string rendering of the table.
    """
    header_cols = [
        'Attack', 'N', 'Success Rate', 'Mean (µs)',
        'Std (µs)', 'P50 (µs)', 'P95 (µs)', 'P99 (µs)',
    ]

    rows = []
    for atk_name, res in results_dict.items():
        n = res.get('n_iterations', 0)
        sr = res.get('success_rate', 0.0)
        mean = res.get('mean_latency_us', 0.0)
        std = res.get('std_latency_us', 0.0)
        p50 = res.get('p50_us', 0.0)
        p95 = res.get('p95_us', 0.0)
        p99 = res.get('p99_us', 0.0)

        rows.append([
            atk_name,
            str(n),
            f"{sr * 100:.1f}%",
            f"{mean:.4f}",
            f"{std:.4f}",
            f"{p50:.4f}",
            f"{p95:.4f}",
            f"{p99:.4f}",
        ])

    # Compute column widths
    col_widths = [len(h) for h in header_cols]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    def _row_str(cells: list) -> str:
        parts = [cell.ljust(col_widths[i]) for i, cell in enumerate(cells)]
        return '| ' + ' | '.join(parts) + ' |'

    separator = '+' + '+'.join('-' * (w + 2) for w in col_widths) + '+'

    lines = [
        '',
        'TABLE II: FMAttack Monte Carlo Experiment Results (N=1000 iterations each)',
        separator,
        _row_str(header_cols),
        separator,
    ]
    for row in rows:
        lines.append(_row_str(row))
    lines.append(separator)
    lines.append('')

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# TABLE I: Gap analysis matrix
# ---------------------------------------------------------------------------

def format_gap_analysis() -> str:
    """
    Format a TABLE I ASCII matrix showing which gaps each attack exploits.

    Returns:
        Multi-line ASCII string of the gap/attack mapping.
    """
    gaps = [
        ('GAP-1', 'No auth field in FM API payload',
         'Any MCTP endpoint can issue privileged FM commands'),
        ('GAP-2', 'SPDM binding is optional (CAN not SHALL)',
         'Session crypto skipped; tunnels run unauthenticated'),
        ('GAP-3', 'FM SW routing table diverges from HW DRT',
         'Routing inconsistency undetected; enables silent rebind'),
        ('GAP-4', 'DCD extents lack cryptographic device binding',
         'FM can revoke extents without device-side verification'),
        ('GAP-5', 'CXL Tunnel inner-command has no attestation',
         'Arbitrary inner payloads forwarded without verification'),
    ]

    attacks = ['ATK-1', 'ATK-2', 'ATK-3', 'ATK-4']

    exploit_matrix = {
        ('GAP-1', 'ATK-1'): True,
        ('GAP-1', 'ATK-2'): True,
        ('GAP-1', 'ATK-3'): True,
        ('GAP-1', 'ATK-4'): True,
        ('GAP-2', 'ATK-1'): True,
        ('GAP-3', 'ATK-1'): True,
        ('GAP-3', 'ATK-2'): True,
        ('GAP-4', 'ATK-3'): True,
        ('GAP-5', 'ATK-4'): True,
    }

    col_gap = 6
    col_desc = 38
    col_impact = 52
    atk_col = 8

    sep_total = col_gap + col_desc + col_impact + atk_col * len(attacks) + 3 + 2 * len(attacks)
    sep = '+' + '-' * sep_total + '+'

    def _pad(s: str, width: int) -> str:
        if len(s) > width:
            s = s[:width - 1] + '~'
        return s.ljust(width)

    header = (
        '| '
        + _pad('Gap', col_gap)
        + ' | '
        + _pad('Normative Deficiency', col_desc)
        + ' | '
        + _pad('Impact', col_impact)
        + ' | '
        + ' | '.join(_pad(a, atk_col) for a in attacks)
        + ' |'
    )

    lines = [
        '',
        'TABLE I: FMAttack Normative Gap Analysis',
        sep,
        header,
        sep,
    ]

    for gap_id, desc, impact in gaps:
        marks = [
            '  [X]  ' if exploit_matrix.get((gap_id, atk)) else '       '
            for atk in attacks
        ]
        row = (
            '| '
            + _pad(gap_id, col_gap)
            + ' | '
            + _pad(desc, col_desc)
            + ' | '
            + _pad(impact, col_impact)
            + ' | '
            + ' | '.join(marks)
            + ' |'
        )
        lines.append(row)

    lines.append(sep)
    lines.append('')

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Message Sequence Diagrams
# ---------------------------------------------------------------------------

_MSC_TEMPLATES: Dict[str, str] = {
    'ATK-1 VPPB-REBIND': """\
ATK-1 VPPB-REBIND  Message Sequence Diagram
============================================

  Attacker (TenantB)    MCTP Bus         FM Daemon         CXL Switch
       |                    |                |                   |
       |  BIND_VPPB (0x5200)|                |                   |
       |  {vcs=0,vppb=1,    |                |                   |
       |   port=2,          |                |                   |
       |   tenant=TenantB}  |                |                   |
       |------------------->|                |                   |
       |                    |  dispatch cmd  |                   |
       |                    |--------------->|                   |
       |                    |                | [GAP-1] No auth   |
       |                    |                | check performed   |
       |                    |                |                   |
       |                    |                | bind_vppb()       |
       |                    |                |------------------>|
       |                    |                |                   | HW DRT updated
       |                    |                |                   | vppb_ownership
       |                    |                |                   | → TenantB
       |                    |                |<------------------|
       |                    |                | [GAP-3] SW table  |
       |                    |                | NOT synced →      |
       |                    |                | divergence begins |
       |                    |<---------------|                   |
       |  success=True      |                |                   |
       |<-------------------|                |                   |
       |                    |                |                   |
  [TenantA's vPPB stolen; TenantB can now access victim memory]
""",

    'ATK-2 PORTDOS': """\
ATK-2 PORTDOS  Message Sequence Diagram
========================================

  Attacker (TenantB)    MCTP Bus         FM Daemon         CXL Switch
       |                    |                |                   |
       |  SET_PORT_STATE     |                |                   |
       |  (0x5702)          |                |                   |
       |  {port=1,          |                |                   |
       |   state=DISABLED,  |                |                   |
       |   tenant=TenantB}  |                |                   |
       |------------------->|                |                   |
       |                    |  dispatch cmd  |                   |
       |                    |--------------->|                   |
       |                    |                | [GAP-1] No owner  |
       |                    |                | check; TenantA    |
       |                    |                | not consulted     |
       |                    |                |                   |
       |                    |                | set_port_state()  |
       |                    |                |------------------>|
       |                    |                |                   | port[1].state
       |                    |                |                   | = DISABLED
       |                    |                |<------------------|
       |                    |                | [GAP-3] FM SW     |
       |                    |                | still ENABLED     |
       |                    |<---------------|                   |
       |  success=True      |                |                   |
       |<-------------------|                |                   |
       |                    |                |                   |
  [TenantA's port disabled; all traffic blocked → DoS]
""",

    'ATK-3 DCDRAIN': """\
ATK-3 DCDRAIN  Message Sequence Diagram
========================================

  Attacker (TenantB)    MCTP Bus         FM Daemon         CXL Switch      DCD Device
       |                    |                |                   |                |
       |  RELEASE_DCD_EXTENT|                |                   |                |
       |  (0x5603)          |                |                   |                |
       |  {region=0,        |                |                   |                |
       |   start=0,         |                |                   |                |
       |   len=1GiB,        |                |                   |                |
       |   tenant=TenantA}  |                |                   |                |
       |------------------->|                |                   |                |
       |                    |  dispatch cmd  |                   |                |
       |                    |--------------->|                   |                |
       |                    |                | [GAP-1] No auth   |                |
       |                    |                | check; no proof   |                |
       |                    |                | of ownership      |                |
       |                    |                |                   |                |
       |                    |                | remove_dcd_extent |                |
       |                    |                |------------------>|                |
       |                    |                |                   | extent removed |
       |                    |                |                   |--------------->|
       |                    |                |                   |                | [GAP-4]
       |                    |                |                   |                | No crypto
       |                    |                |                   |                | binding
       |                    |                |                   |                | checked
       |                    |                |                   |<---------------|
       |                    |                |<------------------|                |
       |                    |<---------------|                   |                |
       |  success=True      |                |                   |                |
       |<-------------------|                |                   |                |
       |                    |                |                   |                |
  [TenantA.crash() called; LLM workload halted; tokens_after == tokens_before]
""",

    'ATK-4 TUNNELSPOOF': """\
ATK-4 TUNNELSPOOF  Message Sequence Diagram
============================================

  Attacker (TenantB)    MCTP Bus         FM Daemon         CXL Switch    LD (target)
       |                    |                |                   |               |
       | TUNNEL_MANAGEMENT  |                |                   |               |
       | (0x5705)           |                |                   |               |
       | {tunnel=1,         |                |                   |               |
       |  inner: BIND_VPPB  |                |                   |               |
       |  bytes (0x5200…),  |                |                   |               |
       |  src=TenantB.eid}  |                |                   |               |
       |------------------->|                |                   |               |
       |                    |  dispatch cmd  |                   |               |
       |                    |--------------->|                   |               |
       |                    |                | [GAP-1] No auth   |               |
       |                    |                | on outer envelope |               |
       |                    |                |                   |               |
       |                    |                | inject_through_   |               |
       |                    |                | tunnel()          |               |
       |                    |                |------------------>|               |
       |                    |                |                   | [GAP-5] inner |
       |                    |                |                   | bytes NOT     |
       |                    |                |                   | attested      |
       |                    |                |                   |               |
       |                    |                |                   | forward inner |
       |                    |                |                   |-------------->|
       |                    |                |                   |               | processes
       |                    |                |                   |               | spoofed
       |                    |                |                   |               | BIND_VPPB
       |                    |                |                   |<--------------|
       |                    |                |<------------------|               |
       |                    |<---------------|                   |               |
       |  success=True      |                |                   |               |
       |  auth=False        |                |                   |               |
       |<-------------------|                |                   |               |
       |                    |                |                   |               |
  [Fabricated FM command executed on downstream LD without any attestation]
""",
}


def format_message_sequence(attack_name: str) -> str:
    """
    Return an ASCII art message sequence diagram for the specified attack.

    Args:
        attack_name: One of 'ATK-1 VPPB-REBIND', 'ATK-2 PORTDOS',
                     'ATK-3 DCDRAIN', 'ATK-4 TUNNELSPOOF'.

    Returns:
        Multi-line ASCII string of the message sequence diagram, or an
        informative error string if the attack name is not recognised.
    """
    template = _MSC_TEMPLATES.get(attack_name)
    if template is None:
        known = ', '.join(f"'{k}'" for k in _MSC_TEMPLATES)
        return (
            f"[format_message_sequence] Unknown attack '{attack_name}'. "
            f"Known attacks: {known}"
        )
    return template
