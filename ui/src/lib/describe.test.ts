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

    // Every verb the switch recognises, crossed with the three ways a
    // request can be missing the pieces a sentence needs: no name (a
    // generateName create, or a malformed row), no resource, or both.
    // None of these combinations may produce a double space, a trailing
    // space, or an empty sentence — whatever the wording ends up being.
    const verbs = ['delete', 'deletecollection', 'create', 'update', 'patch', 'get', 'list', 'watch'];
    const gaps: Array<[string, { resource: string; name: string }]> = [
      ['empty name', { resource: 'pods', name: '' }],
      ['empty resource', { resource: '', name: 'x' }],
      ['both empty', { resource: '', name: '' }],
    ];
    for (const verb of verbs) {
      describeBlock(`verb ${verb}`, () => {
        it.each(gaps)('%s never produces a malformed sentence', (_label, gap) => {
          const d = describe({ verb, resource: gap.resource, namespace: 'demo', name: gap.name });
          expect(d.sentence.length).toBeGreaterThan(0);
          expect(d.sentence).not.toMatch(/ {2,}/);
          expect(d.sentence).not.toMatch(/\s$/);
        });
      });
    }

    it('create without a name says what kind and where (a generateName request)', () => {
      expect(describe({ verb: 'create', resource: 'pods', namespace: 'demo', name: '' }).sentence).toBe('Create a pod in demo');
    });
  });

  it('hostile names stay text, never interpreted', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const d = describe({ verb: 'delete', resource: 'pods', namespace: 'demo', name: hostile });
    expect(d.sentence).toContain(hostile);
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

    // A plain object literal's lookup reads the prototype chain: these
    // are all real properties (or, for a Map, definitely not) that a
    // resource string could legitimately collide with — a CRD can be
    // named "constructor" or "__proto__" in its plural form. None of
    // these may throw, and none may resolve to anything but the raw
    // string, since they are not in the noun map.
    it.each(['constructor', '__proto__', 'toString', 'hasOwnProperty'])('%s is not read off the prototype', (resource) => {
      expect(() => describe({ verb: 'get', resource, namespace: 'demo', name: 'x' })).not.toThrow();
      const d = describe({ verb: 'get', resource, namespace: 'demo', name: 'x' });
      expect(d.resourceNoun).toBe(resource);
      expect(d.sentence).toBe(`Read the ${resource} x`);
    });
  });

  describeBlock('unrecognised subresources render literally (spec §5: nothing is hidden)', () => {
    it('delete on an unrecognised subresource does not silently drop it', () => {
      const d = describe({ verb: 'delete', resource: 'pods', subresource: 'proxy', namespace: 'demo', name: 'db-0' });
      expect(d.sentence).toBe('delete pods/proxy demo/db-0');
    });

    it('create on an unrecognised subresource does not silently drop it', () => {
      const d = describe({ verb: 'create', resource: 'pods', subresource: 'eviction', namespace: 'demo', name: 'db-0' });
      expect(d.sentence).toBe('create pods/eviction demo/db-0');
    });

    it('scale read with get (not patch/update) falls to the literal, not the Scale sentence', () => {
      const d = describe({ verb: 'get', resource: 'deployments', subresource: 'scale', namespace: 'demo', name: 'web' });
      expect(d.sentence).toBe('get deployments/scale demo/web');
    });
  });

  describeBlock('certificate signing request approval is authority', () => {
    it('approving a CSR grants access', () => {
      const d = describe({ verb: 'update', resource: 'certificatesigningrequests', subresource: 'approval', namespace: '', name: 'csr-1' });
      expect(d.sentence).toBe('Grant access with the certificate signing request csr-1');
    });

    it('reading a CSR approval is not authority-framed (no write verb)', () => {
      const d = describe({ verb: 'get', resource: 'certificatesigningrequests', subresource: 'approval', namespace: '', name: 'csr-1' });
      expect(d.sentence).not.toContain('Grant access');
    });
  });

  describeBlock('authority is gated on write verbs', () => {
    it('deleting a cluster role binding reads as a plain delete, not a grant', () => {
      const d = describe({ verb: 'delete', group: 'rbac.authorization.k8s.io', resource: 'clusterrolebindings', namespace: '', name: 'admin-x' });
      expect(d.sentence).toBe('Delete the cluster role binding admin-x');
    });
  });

  describeBlock('summary-shaped input (ApprovalSummary: subresource joined into resource, no group)', () => {
    it('exec arrives as resource "pods/exec" with no group', () => {
      const d = describe({ verb: 'create', resource: 'pods/exec', namespace: 'demo', name: 'db-0' });
      expect(d.sentence).toBe('Run a command in db-0');
    });

    it('scale arrives as resource "deployments/scale"', () => {
      const d = describe({ verb: 'patch', resource: 'deployments/scale', namespace: 'demo', name: 'web' });
      expect(d.sentence).toBe('Scale the deployment web');
    });

    it('a role binding write is still authority with no group field at all', () => {
      const d = describe({ verb: 'create', resource: 'rolebindings', namespace: 'demo', name: 'admin-x' });
      expect(d.sentence).toBe('Grant access with the role binding admin-x');
    });

    it('an unrecognised joined subresource still renders literally', () => {
      const d = describe({ verb: 'delete', resource: 'pods/proxy', namespace: 'demo', name: 'db-0' });
      expect(d.sentence).toBe('delete pods/proxy demo/db-0');
    });
  });
});
