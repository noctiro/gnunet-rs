//! Iterative SCC condensation with bounded O(V+E) workspace and no graph recursion.
use super::{Error, Graph, RecordId};
pub(super) fn roots(graph: &Graph, sources_only: bool) -> Result<Vec<RecordId>, Error> {
    let mut labels = Vec::new();
    labels
        .try_reserve_exact(graph.rows.len())
        .map_err(|_| Error::Limit)?;
    for row in &graph.rows {
        labels.push(
            graph
                .labels
                .get(&row.source)
                .ok_or(Error::Order)?
                .bytes
                .as_slice(),
        );
    }
    labels.sort_unstable();
    labels.dedup();
    let count = labels.len();
    let mut representatives = filled(count, usize::MAX)?;
    let mut edges = Vec::new();
    edges
        .try_reserve_exact(graph.rows.len())
        .map_err(|_| Error::Limit)?;
    for (id, row) in graph.rows.iter().enumerate() {
        let source_label = &graph.labels.get(&row.source).ok_or(Error::Order)?.bytes;
        let target_label = &graph.labels.get(&row.target).ok_or(Error::Order)?.bytes;
        let source = labels
            .binary_search(&source_label.as_slice())
            .map_err(|_| Error::Order)?;
        representatives[source] = representatives[source].min(id);
        if let Ok(target) = labels.binary_search(&target_label.as_slice()) {
            edges.push((source, target));
        }
    }
    edges.sort_unstable();
    edges.dedup();
    let forward = Csr::new(count, &edges)?;
    for edge in &mut edges {
        std::mem::swap(&mut edge.0, &mut edge.1);
    }
    edges.sort_unstable();
    let reverse = Csr::new(count, &edges)?;
    drop(edges);
    let mut visited = filled(count, false)?;
    let mut order = Vec::new();
    order.try_reserve_exact(count).map_err(|_| Error::Limit)?;
    let mut stack = Vec::new();
    stack.try_reserve_exact(count).map_err(|_| Error::Limit)?;
    for node in 0..count {
        if visited[node] {
            continue;
        }
        visited[node] = true;
        stack.push((node, forward.offsets[node]));
        while let Some((node, next)) = stack.last_mut() {
            if *next == forward.offsets[*node + 1] {
                let finished = *node;
                let _finished_frame = stack.pop();
                order.push(finished);
                continue;
            }
            let target = forward.destinations[*next];
            *next += 1;
            if !visited[target] {
                visited[target] = true;
                stack.push((target, forward.offsets[target]));
            }
        }
    }
    drop(stack);
    drop(visited);
    let mut components = filled(count, usize::MAX)?;
    let mut roots = Vec::new();
    roots.try_reserve_exact(count).map_err(|_| Error::Limit)?;
    let mut pending = Vec::new();
    pending.try_reserve_exact(count).map_err(|_| Error::Limit)?;
    for &node in order.iter().rev() {
        if components[node] != usize::MAX {
            continue;
        }
        let component = roots.len();
        let mut root = node;
        components[node] = component;
        pending.push(node);
        while let Some(current) = pending.pop() {
            root = root.min(current);
            for &target in reverse.neighbors(current) {
                if components[target] == usize::MAX {
                    components[target] = component;
                    pending.push(target);
                }
            }
        }
        roots.push(root);
    }
    let mut incoming = filled(roots.len(), false)?;
    if sources_only {
        for source in 0..count {
            for &target in forward.neighbors(source) {
                if components[source] != components[target] {
                    incoming[components[target]] = true;
                }
            }
        }
    }
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(roots.len())
        .map_err(|_| Error::Limit)?;
    for (component, node) in roots.into_iter().enumerate() {
        if !incoming[component] {
            selected.push(node);
        }
    }
    selected.sort_unstable();
    let mut result = Vec::new();
    result
        .try_reserve_exact(selected.len())
        .map_err(|_| Error::Limit)?;
    result.extend(
        selected
            .into_iter()
            .map(|node| RecordId(representatives[node])),
    );
    Ok(result)
}
struct Csr {
    offsets: Vec<usize>,
    destinations: Vec<usize>,
}
impl Csr {
    fn new(count: usize, edges: &[(usize, usize)]) -> Result<Self, Error> {
        let mut offsets = filled(count.checked_add(1).ok_or(Error::Limit)?, 0usize)?;
        let mut destinations = Vec::new();
        destinations
            .try_reserve_exact(edges.len())
            .map_err(|_| Error::Limit)?;
        for &(source, target) in edges {
            offsets[source + 1] += 1;
            destinations.push(target);
        }
        for node in 1..offsets.len() {
            offsets[node] += offsets[node - 1];
        }
        Ok(Self {
            offsets,
            destinations,
        })
    }
    fn neighbors(&self, node: usize) -> &[usize] {
        &self.destinations[self.offsets[node]..self.offsets[node + 1]]
    }
}
fn filled<T: Clone>(length: usize, value: T) -> Result<Vec<T>, Error> {
    let mut result = Vec::new();
    result.try_reserve_exact(length).map_err(|_| Error::Limit)?;
    result.resize(length, value);
    Ok(result)
}
