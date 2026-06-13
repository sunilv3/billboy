"""Business-logic oracle tests — both the vulnerable case AND the control case.

The control (negative) cases are the important ones: they prove the oracle does
NOT fire when the application correctly rejects the abuse, which is what keeps
business-logic findings from becoming false positives on a paid engagement.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.modules.web.bizlogic_oracles import (
    price_tampering_verdict, negative_value_verdict, coupon_reuse_verdict,
    idor_verdict, forced_browse_verdict, escalation_verdict, workflow_bypass_verdict,
    is_price_field, looks_like_workflow_terminal, looks_like_privileged_path,
)


class TestPriceTampering:
    def test_lowered_price_accepted_and_reflected_is_high(self):
        v = price_tampering_verdict(200, 'Order placed! Total: 0.01', original_value=99.0, tampered_value=0.01)
        assert v.vuln and v.confidence == 'high'

    def test_lowered_price_accepted_medium(self):
        v = price_tampering_verdict(302, 'Redirecting to your order', original_value=99.0, tampered_value=1.0)
        assert v.vuln and v.confidence == 'medium'

    def test_rejected_is_not_vuln(self):
        v = price_tampering_verdict(400, 'Error: price cannot be negative', original_value=99.0, tampered_value=-5.0)
        assert not v.vuln

    def test_price_not_actually_lowered_is_not_vuln(self):
        v = price_tampering_verdict(200, 'Order placed', original_value=10.0, tampered_value=20.0)
        assert not v.vuln


class TestNegativeValue:
    def test_negative_accepted_high(self):
        v = negative_value_verdict(200, 'Thank you, order confirmed', value='-5')
        assert v.vuln and v.confidence == 'high'

    def test_negative_rejected_control(self):
        v = negative_value_verdict(200, 'Quantity must be at least 1', value='-5')
        assert not v.vuln

    def test_positive_value_ignored(self):
        assert not negative_value_verdict(200, 'ok', value='3').vuln


class TestCouponReuse:
    def test_double_apply_succeeds(self):
        v = coupon_reuse_verdict(200, 'Discount applied', 200, 'Discount applied')
        assert v.vuln

    def test_second_apply_rejected_control(self):
        v = coupon_reuse_verdict(200, 'Discount applied', 200, 'Coupon already used')
        assert not v.vuln


class TestIDOR:
    def test_other_principal_data_returned(self):
        v = idor_verdict(
            200, 'Alice profile, order #1, shipping to 1 Main St, card ending 1111',
            200, 'Bob profile, order #2, shipping to 5th Ave, card ending 2222, phone 555')
        assert v.vuln

    def test_access_denied_control(self):
        v = idor_verdict(200, 'Alice', 200, 'Error: access denied')
        assert not v.vuln

    def test_identical_content_is_public_not_idor(self):
        same = 'Public listing page ' * 10
        assert not idor_verdict(200, same, 200, same).vuln

    def test_other_404_not_idor(self):
        assert not idor_verdict(200, 'Alice data here is long enough', 404, 'not found').vuln


class TestForcedBrowse:
    def test_priv_content_unauth_is_high(self):
        v = forced_browse_verdict(200, '<h1>Admin Dashboard</h1> Manage all users, roles')
        assert v.vuln and v.confidence == 'high'

    def test_redirect_to_login_control(self):
        v = forced_browse_verdict(200, 'Please sign in to continue')
        assert not v.vuln

    def test_protected_status_control(self):
        assert not forced_browse_verdict(403, 'forbidden').vuln


class TestEscalation:
    def test_priv_appears_only_after_tamper(self):
        v = escalation_verdict(200, 'role: user, name: bob',
                               200, 'role: admin, privilege: superuser')
        assert v.vuln and v.confidence == 'high'

    def test_no_change_control(self):
        v = escalation_verdict(200, 'name: bob', 200, 'name: bob')
        assert not v.vuln

    def test_baseline_already_priv_not_escalation(self):
        v = escalation_verdict(200, 'admin panel', 200, 'admin panel')
        assert not v.vuln


class TestWorkflowBypass:
    def test_terminal_step_direct_success(self):
        v = workflow_bypass_verdict(200, 'Your order is confirmed')
        assert v.vuln

    def test_terminal_step_blocked_control(self):
        v = workflow_bypass_verdict(403, 'complete the previous step first')
        assert not v.vuln


class TestClassifiers:
    def test_price_field_detection(self):
        assert is_price_field('item_price') and is_price_field('qty') and not is_price_field('username')

    def test_workflow_terminal_paths(self):
        assert looks_like_workflow_terminal('/checkout/complete')
        assert not looks_like_workflow_terminal('/products/list')

    def test_privileged_paths(self):
        assert looks_like_privileged_path('/admin/users')
        assert not looks_like_privileged_path('/about')
