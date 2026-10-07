#!/usr/bin/env python3
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import statistics
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[4]
CASES = ('live_routing', 'storage_contention')


def command(arguments, **kwargs):
    return subprocess.run(arguments, check=True, cwd=ROOT, **kwargs)


def fingerprint():
    files = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    digest = hashlib.sha256()
    for name in sorted(set(files)):
        if name.endswith('.rs') or name.endswith('Cargo.toml') or name == 'Cargo.lock' or name.startswith('.cargo/'):
            digest.update(name.encode() + b'\0' + (ROOT / name).read_bytes() + b'\0')
    return digest.hexdigest()


def build(directory, parent):
    source = directory / 'parent-source'
    source.mkdir(exist_ok=True)
    archive = subprocess.check_output(['git', 'archive', parent], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
        tree.extractall(source, filter='data')
    with (directory / 'parent-build.log').open('w') as log:
        command(['cargo', 'build', '--release', '-p', 'lonewolf', '--manifest-path', str(source / 'Cargo.toml')],
                env={**os.environ, 'CARGO_TARGET_DIR': str(directory / 'parent-target')}, stdout=log, stderr=subprocess.STDOUT)
    with (directory / 'final-build.jsonl').open('w') as log:
        command(['cargo', 'test', '--release', '-p', 'lonewolf', '--test', 'capacity', '--no-run', '--message-format=json'], stdout=log)
    artifacts = [json.loads(line) for line in (directory / 'final-build.jsonl').read_text().splitlines()]
    driver = next(item['executable'] for item in artifacts if item.get('reason') == 'compiler-artifact' and item['target']['name'] == 'capacity' and item.get('executable'))
    binary = next(item['executable'] for item in artifacts if item.get('reason') == 'compiler-artifact' and item['target']['name'] == 'lonewolf' and item.get('executable'))
    return Path(driver), {'A': directory / 'parent-target/release/lonewolf', 'B': Path(binary)}


def run(driver, binaries, directory, name, case, variant, provenance, repetitions=1, multiplier=1, poll=False):
    output = directory / (name + '.json')
    env = {**os.environ, 'LONEWOLF_CAPACITY_SERVER_BIN': str(binaries[variant]), 'LONEWOLF_CAPACITY_CASE': case,
           'LONEWOLF_CAPACITY_REPETITIONS': str(repetitions), 'LONEWOLF_CAPACITY_MULTIPLIER': str(multiplier),
           'LONEWOLF_CAPACITY_OUTPUT': str(output), 'LONEWOLF_CAPACITY_PROVENANCE': json.dumps(provenance[variant])}
    env.pop('LONEWOLF_CAPACITY_POLL', None)
    if poll:
        env['LONEWOLF_CAPACITY_POLL'] = '1'
    print(name, flush=True)
    with (directory / (name + '.log')).open('w') as log:
        command([str(driver), '--exact', 'server_capacity_baseline', '--ignored', '--nocapture'], env=env, stdout=log, stderr=subprocess.STDOUT)
    return json.loads(output.read_text())


def comparison(runs, case):
    rate = 'delivered_messages_per_second' if case == 'live_routing' else 'completed_pairs_per_second'
    latency = 'send_to_receive' if case == 'live_routing' else 'message_to_barrier'
    median = lambda variant, metric: statistics.median(metric(item[variant]['results'][0]['measurement']) for item in runs)
    rates = {variant: median(variant, lambda item: item[rate]) for variant in 'AB'}
    tails = {variant: median(variant, lambda item: item[latency]['p99_us']) for variant in 'AB'}
    cpu = {variant: median(variant, lambda item: sum(item['activity']['server_user_system_cpu_ticks'])) for variant in 'AB'}
    driver_cpu = {variant: median(variant, lambda item: sum(item['activity']['driver_user_system_cpu_ticks'])) for variant in 'AB'}
    loss = (1 - rates['B'] / rates['A']) * 100
    increase = (tails['B'] / tails['A'] - 1) * 100
    return {'median_throughput': rates, 'median_p99_us': tails, 'median_server_cpu_ticks': cpu,
            'median_driver_cpu_ticks': driver_cpu, 'throughput_loss_percent': loss, 'p99_increase_percent': increase,
            'server_cpu_increase_percent': (cpu['B'] / cpu['A'] - 1) * 100 if cpu['A'] else None,
            'driver_cpu_increase_percent': (driver_cpu['B'] / driver_cpu['A'] - 1) * 100 if driver_cpu['A'] else None,
            'investigation_threshold_crossed': loss > 10 or increase > 20}


def samples(values):
    rss = [item['rss_bytes'] for item in values if item['rss_bytes'] is not None]
    result = {'sample_count': len(values), 'rss_sources': sorted({item['rss_source'] for item in values}), 'rss_bytes': {'min': min(rss), 'median': statistics.median(rss), 'max': max(rss)} if rss else None}
    for name in ('server_cpu_ticks', 'driver_cpu_ticks'):
        readings = [item[name] for item in values if item.get(name) is not None]
        result[name + '_observed_interval_delta'] = [readings[-1][index] - readings[0][index] for index in range(2)] if len(readings) >= 2 else None
    missing = [item['socket_memory'] for item in values if not item['socket_memory']['available']]
    result['socket_unavailable_samples'] = len(missing)
    if missing:
        result['socket_unavailable_reasons'] = sorted({item['reason'] for item in missing})
    available = [item['socket_memory'] for item in values if item['socket_memory']['available']]
    if not available:
        result['socket_memory'] = {'components': None, 'reason': values[0]['socket_memory'].get('reason', 'no samples') if values else 'no samples'}
    else:
        result['socket_memory'] = {'connected_socket_count_range': [min(item['connected_socket_count'] for item in available), max(item['connected_socket_count'] for item in available)],
            'component_peaks_bytes': {key: max(item['components'][key] for item in available) for key in available[0]['components']},
            'component_medians_bytes': {key: statistics.median(item['components'][key] for item in available) for key in available[0]['components']}}
    return result


def compact(value):
    if isinstance(value, list):
        return [compact(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key.endswith('samples') and isinstance(item, list) and item and isinstance(item[0], dict) and 'rss_bytes' in item[0]:
            result[key] = samples(item)
        elif key == 'upper_bounds_us':
            continue
        elif key == 'poll_snapshots':
            result['diagnostics_poll_count'] = len(item)
        else:
            result[key] = compact(item)
    if 'cold_samples' in result and 'bound_samples' in result:
        delta = result['bound_samples']['rss_bytes']['median'] - result['cold_samples']['rss_bytes']['median']
        result['rss_increment_bytes'] = delta
        result['rss_increment_per_bound_resource_bytes'] = delta / 64
    if 'before_samples' in result and 'after_samples' in result:
        result['retained_rss_increment_bytes'] = result['after_samples']['rss_bytes']['median'] - result['before_samples']['rss_bytes']['median']
    return result



def compact_diagnostics(value):
    if value is None:
        return None
    pool = {key: item for key, item in value['pool'].items() if key not in ('buckets', 'reserved_bytes')}
    pool['bucket_activity'] = [[item['available_chunks'], item['allocations_total']] for item in value['pool']['buckets']]
    histograms = {}
    for name, item in value['histograms'].items():
        if not any(item[key] for key in ('count', 'sum_us', 'abandoned_total', 'in_flight')) and not any(item['buckets']):
            continue
        histogram = {key: item[key] for key in ('count', 'sum_us', 'abandoned_total', 'in_flight')}
        histogram['nonzero_buckets'] = [[index, count] for index, count in enumerate(item['buckets']) if count]
        histograms[name] = histogram
    return {'counters': value['counters'], 'gauges': value['gauges'], 'histograms': histograms, 'pool': pool}


def compact_measurement(value, diagnostics=True):
    result = compact({key: item for key, item in value.items() if not key.endswith('diagnostics')})
    if diagnostics:
        for key, item in value.items():
            if key.endswith('diagnostics'):
                result[key] = compact_diagnostics(item)
    return result


def compact_report(report):
    baseline = report['baseline']
    pool = baseline['results'][0]['measurement']['cold_diagnostics']['pool']
    result = {key: value for key, value in report.items() if key not in ('baseline', 'paired_comparisons', 'investigations', 'one_hz_polling')}
    result['environment'] = baseline['metadata']
    result['configuration'] = baseline['configuration']
    first = report['paired_comparisons']['live_routing']['runs'][0]
    result['server_binary_sha256'] = {variant: first[variant]['server_binary_sha256'] for variant in 'AB'}
    result['aggregation'] = {'memory_samples': 'ranges and medians; CPU deltas cover the observed sample interval',
        'histograms': 'omitted histograms and omitted bucket indices are zero; bucket indices refer to histogram_upper_bounds_us plus overflow',
        'bucket_activity_columns': ['available_chunks', 'allocations_total'], 'pool_reserved_bytes': pool['reserved_bytes'],
        'pool_bucket_layout': [{key: bucket[key] for key in ('chunk_bytes', 'total_chunks', 'shard_count')} for bucket in pool['buckets']]}
    result['baseline_repetitions'] = [{'case': item['case'], 'repetition': item['repetition'], 'measurement': compact_measurement(item['measurement'])} for item in baseline['results']]
    for section in ('paired_comparisons', 'investigations'):
        result[section] = {}
        for case, item in report[section].items():
            records = []
            for pair in item['runs']:
                records.append({'pair': pair['pair'], 'order': pair['order'], **{variant: compact_measurement(pair[variant]['results'][0]['measurement'], False) for variant in 'AB'}})
            result[section][case] = {**{key: value for key, value in item.items() if key != 'runs'}, 'runs': records}
    result['one_hz_polling'] = compact_measurement(report['one_hz_polling']['results'][0]['measurement'], False)
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--parent', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--report', type=Path, default=ROOT / 'docs/capacity-baseline.json')
    options = parser.parse_args()
    directory = options.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip()
    source_hash = fingerprint()
    provenance = {'A': {'revision': options.parent, 'source': 'git archive of exact parent revision'},
                  'B': {'base_revision': base, 'dirty_source_sha256': source_hash, 'source': 'uncommitted implementation tree; fingerprint includes Cargo manifests/lock, Rust sources and .cargo files'}}
    driver, binaries = build(directory, options.parent)
    pairs = {}
    investigations = {}
    for case in CASES:
        records = []
        for number, order in enumerate(('AB', 'BA', 'AB'), 1):
            record = {'pair': number, 'order': order}
            for variant in order:
                record[variant] = run(driver, binaries, directory, f'{case}-pair-{number}-{variant}', case, variant, provenance)
            records.append(record)
        summary = comparison(records, case)
        print(case, json.dumps(summary), flush=True)
        pairs[case] = {'runs': records, 'comparison': summary}
        if summary['investigation_threshold_crossed']:
            extended = []
            for number in range(1, 6):
                order = 'AB' if number % 2 else 'BA'
                record = {'pair': number, 'order': order}
                for variant in order:
                    record[variant] = run(driver, binaries, directory, f'{case}-extended-{number}-{variant}', case, variant, provenance, multiplier=5)
                extended.append(record)
            investigations[case] = {'message_multiplier': 5, 'runs': extended, 'comparison': comparison(extended, case)}
            print(case, 'extended', json.dumps(investigations[case]['comparison']), flush=True)
    baseline = run(driver, binaries, directory, 'baseline', 'all', 'B', provenance, repetitions=3)
    polled = run(driver, binaries, directory, 'live-polled', 'live_routing', 'B', provenance, poll=True)
    files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.glob('*.json')}
    report = {'schema_version': 1, 'provenance': provenance, 'driver_binary_sha256': hashlib.sha256(driver.read_bytes()).hexdigest(),
        'rustflags': os.environ.get('RUSTFLAGS', ''), 'cargo_profile': 'release', 'histogram_upper_bounds_us': [10,50,100,500,1000,5000,10000,50000,100000,500000,1000000,5000000],
        'baseline': baseline, 'paired_comparisons': pairs, 'investigations': investigations, 'one_hz_polling': polled,
        'raw_result_file_sha256': files}
    options.report.parent.mkdir(parents=True, exist_ok=True)
    (directory / 'full-report.json').write_text(json.dumps(report) + '\n')
    options.report.write_text(json.dumps(compact_report(report), indent=2) + '\n')
    if any(item['comparison']['investigation_threshold_crossed'] for item in investigations.values()):
        raise SystemExit('extended comparison exceeds investigation threshold; report retained for investigation')


if __name__ == '__main__':
    main()
