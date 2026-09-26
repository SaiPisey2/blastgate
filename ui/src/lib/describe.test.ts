import { describe as describeBlock, expect, it } from 'vitest';
import { describe, targetOf } from './describe';

describeBlock('targetOf', () => {
  it('joins namespace and name', () => {
    expect(targetOf({ namespace: 'demo', name: 'data' })).toBe('demo/data');
  });
  it('falls back to the bare name when cluster-scoped', () => {
    expect(targetOf({ namespace: '', name: 'pv-1' })).toBe('pv-1');
  });
  it('is empty when both are empty', () => {
    expect(targetOf({ namespace: '', name: '' })).toBe('');
  });
});

describeBlock('describe', () => {
  it('delete a volume claim', () => {
    const d = describe({ verb: 'delete', resource: 'persistentvolumeclaims', namespace: 'demo', name: 'data' });
    expect(d.sentence).toBe('Delete the volume claim data');
    expect(d.target).toBe('demo/data');
  });

  it('scale', () => {
    const d = describe({ verb: 'patch', resource: 'deployments', subresource: 'scale', name: 'web', namespace: 'demo' });
    expect(d.sentence).toBe('Scale the deployment web');
  });

  describeBlock('exec-family subresources', () => {
    it('exec runs a command', () => {
      expect(describe({ verb: 'create', resource: 'pods', subresource: 'exec', name: 'db-0', namespace: 'demo' }).sentence).toBe(
        'Run a command in db-0',
      );
    });
    it('attach', () => {
      expect(describe({ verb: 'create', resource: 'pods', subresource: 'attach', name: 'db-0', namespace: 'demo' }).sentence).toBe(
        'Attach to db-0',
      );
    });
    it('portforward', () => {
      expect(describe({ verb: 'create', resource: 'pods', subresource: 'portforward', name: 'db-0', namespace: 'demo' }).sentence).toBe(
        'Forward a port to db-0',
      );
    });
    it('ephemeralcontainers', () => {
      expect(
        describe({ verb: 'create', resource: 'pods', subresource: 'ephemeralcontainers', name: 'db-0', namespace: 'demo' }).sentence,
      ).toBe('Add a debug container to db-0');
    });
    it('log', () => {
      expect(describe({ verb: 'get', resource: 'pods', subresource: 'log', name: 'db-0', namespace: 'demo' }).sentence).toBe(
        'Read the logs of db-0',
      );
    });
  });

  describeBlock('reads', () => {
    it('get with a name reads one', () => {
      expect(describe({ verb: 'get', resource: 'pods', namespace: 'demo', name: 'x' }).sentence).toBe('Read the pod x');
    });
    it('list reads the collection', () => {
      expect(describe({ verb: 'list', resource: 'pods', namespace: 'demo', name: '' }).sentence).toBe('Read the list of pods');
    });
    it('watch', () => {
      expect(describe({ verb: 'watch', resource: 'deployments', namespace: 'demo', name: '' }).sentence).toBe('Watch deployments');
    });
  });

  describeBlock('deletecollection', () => {
    it('namespaced', () => {
      expect(describe({ verb: 'deletecollection', resource: 'pods', namespace: 'demo', name: '' }).sentence).toBe(
        'Delete every pod in demo',
      );
    });
    it('cluster-scoped', () => {
      expect(describe({ verb: 'deletecollection', resource: 'persistentvolumes', namespace: '', name: '' }).sentence).toBe(
        'Delete every volume',
      );
    });
  });

  describeBlock('create and update', () => {
    it('create a configmap', () => {
      expect(describe({ verb: 'create', resource: 'configmaps', namespace: 'demo', name: 'x' }).sentence).toBe('Create the config map x');
    });
    it('update a deployment', () => {
      expect(describe({ verb: 'update', resource: 'deployments', namespace: 'demo', name: 'web' }).sentence).toBe(
        'Change the deployment web',
      );
    });
    it('patch a deployment', () => {
      expect(describe({ verb: 'patch', resource: 'deployments', namespace: 'demo', name: 'web' }).sentence).toBe(
        'Change the deployment web',
      );
    });
  });

  describeBlock('authority resources', () => {
    const group = 'rbac.authorization.k8s.io';
    it('clusterrolebindings', () => {
      expect(
        describe({ verb: 'create', group, resource: 'clusterrolebindings', namespace: '', name: 'admin-x' }).sentence,
      ).toBe('Grant access with the cluster role binding admin-x');
    });
    it('rolebindings', () => {
      expect(describe({ verb: 'create', group, resource: 'rolebindings', namespace: 'demo', name: 'admin-x' }).sentence).toBe(
        'Grant access with the role binding admin-x',
      );
    });
    it('clusterroles', () => {
      expect(describe({ verb: 'create', group, resource: 'clusterroles', namespace: '', name: 'admin-x' }).sentence).toBe(
        'Grant access with the cluster role admin-x',
      );
    });
    it('roles', () => {
      expect(describe({ verb: 'create', group, resource: 'roles', namespace: 'demo', name: 'admin-x' }).sentence).toBe(
        'Grant access with the role admin-x',
      );
    });
    it('serviceaccounts/token', () => {
      expect(
        describe({ verb: 'create', resource: 'serviceaccounts', subresource: 'token', namespace: 'demo', name: 'admin-x' }).sentence,
      ).toBe('Grant access with the service account admin-x');
    });
  });

  describeBlock('unknown actions fall back to the literal request', () => {
    it('unknown verb, resource and subresource', () => {
      const d = describe({ verb: 'frobnicate', resource: 'widgets', subresource: 'spin', namespace: 'n', name: 'w' });
      expect(d.sentence).toBe('frobnicate widgets/spin n/w');
    });
    it('all empty', () => {
      expect(describe({ verb: '', resource: '', namespace: '', name: '' }).sentence).toBe('Unknown request');
    });
    it('the sentence is never empty for any input', () => {
      expect(describe({ verb: '', resource: 'widgets', namespace: '', name: '' }).sentence.length).toBeGreaterThan(0);
      expect(describe({ verb: 'frobnicate', resource: '', namespace: '', name: '' }).sentence.length).toBeGreaterThan(0);
    });
  });

  it('hostile names stay text, never interpreted', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const d = describe({ verb: 'delete', resource: 'pods', namespace: 'demo', name: hostile });
    expect(d.sentence).toContain(hostile);
    expect(typeof d.sentence).toBe('string');
  });

  describeBlock('resource noun map', () => {
    const cases: Array<[string, string, string]> = [
      ['pods', 'pod', 'pods'],
      ['deployments', 'deployment', 'deployments'],
      ['statefulsets', 'stateful set', 'stateful sets'],
      ['daemonsets', 'daemon set', 'daemon sets'],
      ['replicasets', 'replica set', 'replica sets'],
      ['jobs', 'job', 'jobs'],
      ['cronjobs', 'cron job', 'cron jobs'],
      ['services', 'service', 'services'],
      ['configmaps', 'config map', 'config maps'],
      ['secrets', 'secret', 'secrets'],
      ['persistentvolumeclaims', 'volume claim', 'volume claims'],
      ['persistentvolumes', 'volume', 'volumes'],
      ['namespaces', 'namespace', 'namespaces'],
      ['ingresses', 'ingress', 'ingresses'],
      ['networkpolicies', 'network policy', 'network policies'],
      ['poddisruptionbudgets', 'disruption budget', 'disruption budgets'],
      ['serviceaccounts', 'service account', 'service accounts'],
      ['roles', 'role', 'roles'],
      ['rolebindings', 'role binding', 'role bindings'],
      ['clusterroles', 'cluster role', 'cluster roles'],
      ['clusterrolebindings', 'cluster role binding', 'cluster role bindings'],
      ['nodes', 'node', 'nodes'],
      ['leases', 'lease', 'leases'],
      ['events', 'event', 'events'],
    ];
    it.each(cases)('%s -> singular %s, plural via list %s', (resource, singular, pluralWord) => {
      const single = describe({ verb: 'get', resource, namespace: 'demo', name: 'x' });
      expect(single.resourceNoun).toBe(singular);
      const many = describe({ verb: 'list', resource, namespace: 'demo', name: '' });
      expect(many.sentence).toBe(`Read the list of ${pluralWord}`);
    });

    it('an unknown resource uses the raw resource string', () => {
      const d = describe({ verb: 'get', resource: 'widgets', namespace: 'demo', name: 'x' });
      expect(d.resourceNoun).toBe('widgets');
      expect(d.sentence).toBe('Read the widgets x');
    });
  });
});
