use async_trait::async_trait;
use casbin::{error::AdapterError, Adapter, Error as CasbinError, Filter, Model, Result};
use sea_orm::ConnectionTrait;

use crate::{
    action::{self, Rule, RuleWithType},
    entity, migration,
};

pub struct SeaOrmAdapter<C> {
    conn: C,
    is_filtered: bool,
}

impl<C: ConnectionTrait> SeaOrmAdapter<C> {
    pub async fn new(conn: C) -> Result<Self> {
        migration::up(&conn)
            .await
            .map(|_| Self {
                conn,
                is_filtered: false,
            })
            .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))
    }

    fn save_policy_line<'a>(ptype: &'a str, rule: &'a [String]) -> Option<RuleWithType<'a>> {
        if ptype.trim().is_empty() || rule.is_empty() {
            return None;
        }

        let mut rule_with_type = RuleWithType {
            ptype,
            v0: "",
            v1: "",
            v2: "",
            v3: "",
            v4: "",
            v5: "",
        };

        if let Some(v) = rule.get(0) {
            rule_with_type.v0 = v;
        }
        if let Some(v) = rule.get(1) {
            rule_with_type.v1 = v;
        }
        if let Some(v) = rule.get(2) {
            rule_with_type.v2 = v;
        }
        if let Some(v) = rule.get(3) {
            rule_with_type.v3 = v;
        }
        if let Some(v) = rule.get(4) {
            rule_with_type.v4 = v;
        }
        if let Some(v) = rule.get(5) {
            rule_with_type.v5 = v;
        }

        Some(rule_with_type)
    }

    fn load_policy_line(model: &entity::Model) -> Option<Vec<String>> {
        if model.ptype.chars().next().is_some() {
            return Self::normalize_policy(model);
        }

        None
    }

    fn normalize_policy(model: &entity::Model) -> Option<Vec<String>> {
        let mut result = vec![
            &model.v0, &model.v1, &model.v2, &model.v3, &model.v4, &model.v5,
        ];

        while let Some(last) = result.last() {
            if last.is_empty() {
                result.pop();
            } else {
                break;
            }
        }

        if !result.is_empty() {
            return Some(result.iter().map(|&x| x.to_owned()).collect());
        }

        None
    }
}

#[async_trait]
impl<C: ConnectionTrait + Send + Sync> Adapter for SeaOrmAdapter<C> {
    async fn load_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let rules = action::load_policy(&self.conn).await?;

        for rule in &rules {
            let Some(sec) = rule.ptype.chars().next().map(|x| x.to_string()) else {
                continue;
            };
            let Some(t1) = m.get_mut_model().get_mut(&sec) else {
                continue;
            };
            let Some(t2) = t1.get_mut(&rule.ptype) else {
                continue;
            };
            let Some(line) = Self::load_policy_line(rule) else {
                continue;
            };
            t2.get_mut_policy().insert(line);
        }

        Ok(())
    }

    async fn load_filtered_policy<'a>(&mut self, m: &mut dyn Model, f: Filter<'a>) -> Result<()> {
        let rules = action::load_filtered_policy(&self.conn, &f).await?;
        self.is_filtered = true;

        for rule in &rules {
            let Some(sec) = rule.ptype.chars().next().map(|x| x.to_string()) else {
                continue;
            };
            let Some(t1) = m.get_mut_model().get_mut(&sec) else {
                continue;
            };
            let Some(t2) = t1.get_mut(&rule.ptype) else {
                continue;
            };
            let Some(policy) = Self::normalize_policy(rule) else {
                continue;
            };
            t2.get_mut_policy().insert(policy);
        }

        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let mut rules = vec![];

        if let Some(ast_map) = m.get_model().get("p") {
            for (ptype, ast) in ast_map {
                let new_rules = ast
                    .get_policy()
                    .into_iter()
                    .filter_map(|x| Self::save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                let new_rules = ast
                    .get_policy()
                    .into_iter()
                    .filter_map(|x| Self::save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }
        action::save_policies(&self.conn, &rules).await
    }

    async fn clear_policy(&mut self) -> Result<()> {
        action::clear_policy(&self.conn).await
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }

    async fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let Some(rule_with_type) = Self::save_policy_line(ptype, rule.as_slice()) else {
            return Ok(false);
        };

        action::add_policy(&self.conn, &rule_with_type)
            .await
            .map(|_| true)
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let rules = rules
            .iter()
            .filter_map(|x| Self::save_policy_line(ptype, x))
            .collect::<Vec<_>>();

        action::add_policies(&self.conn, &rules).await.map(|_| true)
    }

    async fn remove_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        action::remove_policy(&self.conn, ptype, &Rule::from(rule.as_ref())).await
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let rules = rules
            .iter()
            .map(|r| Rule::from(r.as_ref()))
            .collect::<Vec<_>>();
        action::remove_policies(&self.conn, ptype, &rules).await
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        if field_index <= 5 && !field_values.is_empty() && field_values.len() >= 6 - field_index {
            Ok(false)
        } else {
            let field_values = if field_values.len() < 6 {
                let mut temp = field_values.clone();
                temp.resize(6, String::new());
                temp
            } else {
                field_values
            };

            let rule: [String; 6] = field_values.try_into().unwrap();
            let mut new_rule: [&str; 6] = Default::default();
            for (i, r) in rule.iter().enumerate() {
                new_rule[i] = r;
            }
            action::remove_filtered_policy(&self.conn, ptype, field_index, &new_rule).await
        }
    }
}

// Copy from https://github.com/casbin-rs/sqlx-adapter/blob/master/src/adapter.rs
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use casbin::Adapter;
    use sea_orm::{ConnectOptions, Database};

    use crate::adapter::SeaOrmAdapter;

    fn to_owned(v: Vec<&str>) -> Vec<String> {
        v.into_iter().map(|x| x.to_owned()).collect()
    }

    #[cfg_attr(
        any(
            feature = "runtime-async-std-native-tls",
            feature = "runtime-async-std-rustls"
        ),
        async_std::test
    )]
    #[cfg_attr(
        any(feature = "runtime-tokio-native-tls", feature = "runtime-tokio-rustls"),
        tokio::test(flavor = "multi_thread")
    )]
    #[cfg_attr(
        any(feature = "runtime-actix-native-tls", feature = "runtime-actix-rustls"),
        actix_rt::test
    )]
    async fn test_adapter() {
        use casbin::prelude::*;

        let file_adapter = FileAdapter::new("examples/rbac_policy.csv");

        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let mut e = Enforcer::new(m, file_adapter).await.unwrap();
        let db_url = {
            #[cfg(feature = "postgres")]
            {
                "postgres://casbin_rs:casbin_rs@localhost:5432/casbin"
            }

            #[cfg(feature = "mysql")]
            {
                "mysql://root:123456@localhost:3306/casbin"
            }

            #[cfg(feature = "sqlite")]
            {
                "sqlite:casbin.db"
            }
        };

        let mut opt = ConnectOptions::new(db_url.to_owned());
        opt.max_connections(100)
            .min_connections(5)
            .connect_timeout(Duration::from_secs(8))
            .acquire_timeout(Duration::from_secs(8))
            .idle_timeout(Duration::from_secs(8))
            .max_lifetime(Duration::from_secs(8));

        let db = Database::connect(opt).await.unwrap();

        let mut adapter = SeaOrmAdapter::new(db).await.unwrap();

        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());

        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .unwrap());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .add_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());

        assert!(adapter
            .remove_policies(
                "",
                "p",
                vec![
                    to_owned(vec!["alice", "data1", "read"]),
                    to_owned(vec!["bob", "data2", "write"]),
                    to_owned(vec!["data2_admin", "data2", "read"]),
                    to_owned(vec!["data2_admin", "data2", "write"]),
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policies(
                "",
                "p",
                vec![
                    to_owned(vec!["alice", "data1", "read"]),
                    to_owned(vec!["bob", "data2", "write"]),
                    to_owned(vec!["data2_admin", "data2", "read"]),
                    to_owned(vec!["data2_admin", "data2", "write"]),
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(!adapter
            .remove_policy(
                "",
                "g",
                to_owned(vec!["alice", "data2_admin", "not_exists"])
            )
            .await
            .unwrap());

        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_err());

        assert!(!adapter
            .remove_filtered_policy(
                "",
                "g",
                0,
                to_owned(vec!["alice", "data2_admin", "not_exists"]),
            )
            .await
            .unwrap());

        assert!(adapter
            .remove_filtered_policy("", "g", 0, to_owned(vec!["alice", "data2_admin"]))
            .await
            .unwrap());

        assert!(adapter
            .add_policy(
                "",
                "g",
                to_owned(vec!["alice", "data2_admin", "domain1", "domain2"]),
            )
            .await
            .is_ok());
        assert!(adapter
            .remove_filtered_policy(
                "",
                "g",
                1,
                to_owned(vec!["data2_admin", "domain1", "domain2"]),
            )
            .await
            .unwrap());

        assert!(adapter
            .add_policy("", "g", to_owned(vec!["carol", "data1_admin"]),)
            .await
            .is_ok());
        assert!(adapter
            .remove_filtered_policy("", "g", 0, to_owned(vec!["carol"]),)
            .await
            .unwrap());
        assert_eq!(vec![String::new(); 0], e.get_roles_for_user("carol", None));

        // shadow the previous enforcer
        let mut e = Enforcer::new(
            "examples/rbac_with_domains_model.conf",
            "examples/rbac_with_domains_policy.csv",
        )
        .await
        .unwrap();

        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());
        e.set_adapter(adapter).await.unwrap();

        let filter = Filter {
            p: vec!["", "domain1"],
            g: vec!["", "", "domain1"],
        };

        e.load_filtered_policy(filter).await.unwrap();
        assert!(e.enforce(("alice", "domain1", "data1", "read")).unwrap());
        assert!(e.enforce(("alice", "domain1", "data1", "write")).unwrap());
        assert!(!e.enforce(("alice", "domain1", "data2", "read")).unwrap());
        assert!(!e.enforce(("alice", "domain1", "data2", "write")).unwrap());
        assert!(!e.enforce(("bob", "domain2", "data2", "read")).unwrap());
        assert!(!e.enforce(("bob", "domain2", "data2", "write")).unwrap());
    }
}
