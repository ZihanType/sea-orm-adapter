use casbin::{error::AdapterError, Error as CasbinError, Filter, Result};
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::{NotSet, Set},
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter,
};

use crate::entity::{self, Column, Entity};

#[derive(Debug, Default)]
pub(crate) struct Rule<'a> {
    pub v0: &'a str,
    pub v1: &'a str,
    pub v2: &'a str,
    pub v3: &'a str,
    pub v4: &'a str,
    pub v5: &'a str,
}

impl<'a> From<&'a [String]> for Rule<'a> {
    fn from(value: &'a [String]) -> Self {
        let mut rule = Rule {
            v0: "",
            v1: "",
            v2: "",
            v3: "",
            v4: "",
            v5: "",
        };

        #[allow(clippy::get_first)]
        if let Some(v) = value.get(0) {
            rule.v0 = v;
        }
        if let Some(v) = value.get(1) {
            rule.v1 = v;
        }
        if let Some(v) = value.get(2) {
            rule.v2 = v;
        }
        if let Some(v) = value.get(3) {
            rule.v3 = v;
        }
        if let Some(v) = value.get(4) {
            rule.v4 = v;
        }
        if let Some(v) = value.get(5) {
            rule.v5 = v;
        }
        rule
    }
}

#[derive(Debug, Default)]
pub(crate) struct RuleWithType<'a> {
    pub ptype: &'a str,
    pub v0: &'a str,
    pub v1: &'a str,
    pub v2: &'a str,
    pub v3: &'a str,
    pub v4: &'a str,
    pub v5: &'a str,
}

pub(crate) async fn remove_policy<'conn, 'rule, C: ConnectionTrait>(
    conn: &'conn C,
    ptype: &'rule str,
    rule: &'rule Rule<'rule>,
) -> Result<bool> {
    Entity::delete_many()
        .filter(Column::Ptype.eq(ptype))
        .filter(Column::V0.eq(rule.v0))
        .filter(Column::V1.eq(rule.v1))
        .filter(Column::V2.eq(rule.v2))
        .filter(Column::V3.eq(rule.v3))
        .filter(Column::V4.eq(rule.v4))
        .filter(Column::V5.eq(rule.v5))
        .exec(conn)
        .await
        .map(|count| count.rows_affected == 1)
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))
}

pub(crate) async fn remove_policies<'conn, 'rule, C: ConnectionTrait>(
    conn: &'conn C,
    ptype: &'rule str,
    rules: &'rule [Rule<'rule>],
) -> Result<bool> {
    for rule in rules {
        remove_policy(conn, ptype, rule).await?;
    }
    Ok(true)
}

pub(crate) async fn remove_filtered_policy<'conn, 'rule, C: ConnectionTrait>(
    conn: &'conn C,
    ptype: &'rule str,
    index_of_match_start: usize,
    rule: &'rule [&'rule str; 6],
) -> Result<bool> {
    let mut conditions = Condition::all().add(Column::Ptype.eq(ptype));

    if index_of_match_start == 0 {
        conditions = conditions
            .add_option((!rule[0].is_empty()).then(|| Column::V0.eq(rule[0])))
            .add_option((!rule[1].is_empty()).then(|| Column::V1.eq(rule[1])))
            .add_option((!rule[2].is_empty()).then(|| Column::V2.eq(rule[2])))
            .add_option((!rule[3].is_empty()).then(|| Column::V3.eq(rule[3])))
            .add_option((!rule[4].is_empty()).then(|| Column::V4.eq(rule[4])))
            .add_option((!rule[5].is_empty()).then(|| Column::V5.eq(rule[5])));
    } else if index_of_match_start == 1 {
        conditions = conditions
            .add_option((!rule[0].is_empty()).then(|| Column::V1.eq(rule[0])))
            .add_option((!rule[1].is_empty()).then(|| Column::V2.eq(rule[1])))
            .add_option((!rule[2].is_empty()).then(|| Column::V3.eq(rule[2])))
            .add_option((!rule[3].is_empty()).then(|| Column::V4.eq(rule[3])))
            .add_option((!rule[4].is_empty()).then(|| Column::V5.eq(rule[4])));
    } else if index_of_match_start == 2 {
        conditions = conditions
            .add_option((!rule[0].is_empty()).then(|| Column::V2.eq(rule[0])))
            .add_option((!rule[1].is_empty()).then(|| Column::V3.eq(rule[1])))
            .add_option((!rule[2].is_empty()).then(|| Column::V4.eq(rule[2])))
            .add_option((!rule[3].is_empty()).then(|| Column::V5.eq(rule[3])));
    } else if index_of_match_start == 3 {
        conditions = conditions
            .add_option((!rule[0].is_empty()).then(|| Column::V3.eq(rule[0])))
            .add_option((!rule[1].is_empty()).then(|| Column::V4.eq(rule[1])))
            .add_option((!rule[2].is_empty()).then(|| Column::V5.eq(rule[2])));
    } else if index_of_match_start == 4 {
        conditions = conditions
            .add_option((!rule[0].is_empty()).then(|| Column::V4.eq(rule[0])))
            .add_option((!rule[1].is_empty()).then(|| Column::V5.eq(rule[1])));
    } else {
        conditions = conditions.add_option((!rule[0].is_empty()).then(|| Column::V5.eq(rule[0])));
    }

    Entity::delete_many()
        .filter(conditions)
        .exec(conn)
        .await
        .map(|count| count.rows_affected >= 1)
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))
}

pub(crate) async fn load_policy<C: ConnectionTrait>(conn: &C) -> Result<Vec<entity::Model>> {
    entity::Entity::find()
        .all(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))
}

pub(crate) async fn load_filtered_policy<'conn, 'filter, C: ConnectionTrait>(
    conn: &'conn C,
    filter: &'filter Filter<'filter>,
) -> Result<Vec<entity::Model>> {
    let (g_filter, p_filter) = filtered_where_values(filter);

    entity::Entity::find()
        .filter(
            Condition::any()
                .add(
                    Condition::all()
                        .add(Column::Ptype.starts_with("g"))
                        .add_option((!g_filter[0].is_empty()).then(|| Column::V0.eq(g_filter[0])))
                        .add_option((!g_filter[1].is_empty()).then(|| Column::V1.eq(g_filter[1])))
                        .add_option((!g_filter[2].is_empty()).then(|| Column::V2.eq(g_filter[2])))
                        .add_option((!g_filter[3].is_empty()).then(|| Column::V3.eq(g_filter[3])))
                        .add_option((!g_filter[4].is_empty()).then(|| Column::V4.eq(g_filter[4])))
                        .add_option((!g_filter[5].is_empty()).then(|| Column::V5.eq(g_filter[5]))),
                )
                .add(
                    Condition::all()
                        .add(Column::Ptype.starts_with("p"))
                        .add_option((!p_filter[0].is_empty()).then(|| Column::V0.eq(p_filter[0])))
                        .add_option((!p_filter[1].is_empty()).then(|| Column::V1.eq(p_filter[1])))
                        .add_option((!p_filter[2].is_empty()).then(|| Column::V2.eq(p_filter[2])))
                        .add_option((!p_filter[3].is_empty()).then(|| Column::V3.eq(p_filter[3])))
                        .add_option((!p_filter[4].is_empty()).then(|| Column::V4.eq(p_filter[4])))
                        .add_option((!p_filter[5].is_empty()).then(|| Column::V5.eq(p_filter[5]))),
                ),
        )
        .all(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))
}

fn filtered_where_values<'a>(filter: &'a Filter<'a>) -> ([&'a str; 6], [&'a str; 6]) {
    let mut g_filter: [&'a str; 6] = ["", "", "", "", "", ""];
    let mut p_filter: [&'a str; 6] = ["", "", "", "", "", ""];

    for (idx, ele) in g_filter.iter_mut().enumerate() {
        match filter.g.get(idx) {
            Some(a) if !a.is_empty() => {
                *ele = a;
            }
            _ => (),
        }
    }

    for (idx, ele) in p_filter.iter_mut().enumerate() {
        match filter.p.get(idx) {
            Some(a) if !a.is_empty() => {
                *ele = a;
            }
            _ => (),
        }
    }

    (g_filter, p_filter)
}

pub(crate) async fn save_policy<'conn, 'rule, C: ConnectionTrait>(
    conn: &'conn C,
    rule: &'rule RuleWithType<'rule>,
) -> Result<()> {
    let models = entity::Entity::find()
        .filter(Column::Ptype.eq(rule.ptype))
        .filter(Column::V0.eq(rule.v0))
        .filter(Column::V1.eq(rule.v1))
        .filter(Column::V2.eq(rule.v2))
        .filter(Column::V3.eq(rule.v3))
        .filter(Column::V4.eq(rule.v4))
        .filter(Column::V5.eq(rule.v5))
        .all(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    if !models.is_empty() {
        return Ok(());
    }

    let model = entity::ActiveModel {
        id: NotSet,
        ptype: Set(rule.ptype.to_string()),
        v0: Set(rule.v0.to_string()),
        v1: Set(rule.v1.to_string()),
        v2: Set(rule.v2.to_string()),
        v3: Set(rule.v3.to_string()),
        v4: Set(rule.v4.to_string()),
        v5: Set(rule.v5.to_string()),
    };

    model
        .insert(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    Ok(())
}

pub(crate) async fn save_policies<'conn, 'rule, C: ConnectionTrait>(
    conn: &'conn C,
    rules: &'rule [RuleWithType<'rule>],
) -> Result<()> {
    for rule in rules {
        save_policy(conn, rule).await?;
    }

    Ok(())
}

pub(crate) async fn add_policy<'conn, 'rule, C: ConnectionTrait>(
    conn: &'conn C,
    rule: &'rule RuleWithType<'rule>,
) -> Result<()> {
    let model = entity::ActiveModel {
        id: NotSet,
        ptype: Set(rule.ptype.to_string()),
        v0: Set(rule.v0.to_string()),
        v1: Set(rule.v1.to_string()),
        v2: Set(rule.v2.to_string()),
        v3: Set(rule.v3.to_string()),
        v4: Set(rule.v4.to_string()),
        v5: Set(rule.v5.to_string()),
    };

    model
        .insert(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    Ok(())
}

pub(crate) async fn add_policies<'conn, 'rule, C: ConnectionTrait>(
    conn: &'conn C,
    rules: &'rule [RuleWithType<'rule>],
) -> Result<()> {
    for rule in rules {
        add_policy(conn, rule).await?;
    }

    Ok(())
}

pub(crate) async fn clear_policy<C: ConnectionTrait>(conn: &C) -> Result<()> {
    entity::Entity::delete_many()
        .exec(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    Ok(())
}
