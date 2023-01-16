use sea_orm::{
    sea_query::{ConditionExpression, IntoCondition},
    Condition, ConditionalStatement, QueryFilter,
};

pub(crate) trait QueryFilterExt: QueryFilter {
    fn filter_maybe<F>(mut self, maybe: bool, filter: F) -> Self
    where
        F: IntoCondition,
    {
        if maybe {
            self.query().cond_where(filter.into_condition());
        }
        self
    }
}

impl<T> QueryFilterExt for T where T: QueryFilter {}

pub(crate) trait ConditionExt {
    fn add_maybe<C>(self, maybe: bool, condition: C) -> Self
    where
        C: Into<ConditionExpression>;
}

impl ConditionExt for Condition {
    fn add_maybe<C>(self, maybe: bool, condition: C) -> Self
    where
        C: Into<ConditionExpression>,
    {
        if maybe {
            self.add(condition)
        } else {
            self
        }
    }
}
