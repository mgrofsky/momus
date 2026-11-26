"""Static checks for deploy/aws/scanner-host.yaml. Offline only: nothing here calls AWS.
Run (needs PyYAML): python3 -B -m unittest deploy/aws/test_template.py   (README.md shows a throwaway container for it)"""
import os
import re
import unittest

import yaml

TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner-host.yaml")


class CfnLoader(yaml.SafeLoader):
    pass


def _tag(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    name = "Ref" if suffix == "Ref" else "Fn::" + suffix
    return {name: value}


CfnLoader.add_multi_constructor("!", _tag)

with open(TEMPLATE) as fh:
    T = yaml.load(fh, Loader=CfnLoader)
R = T["Resources"]


def of_type(kind):
    return {k: v for k, v in R.items() if v["Type"] == kind}


def one(kind):
    found = of_type(kind)
    assert len(found) == 1, f"{kind}: {sorted(found)}"
    return next(iter(found.items()))


def as_list(x):
    return x if isinstance(x, list) else [x]


def strings_in(x):
    """Every string inside x, including those inside intrinsic functions (Fn::Sub, Fn::Join, Fn::Split, Fn::If)."""
    if isinstance(x, str):
        return [x]
    if isinstance(x, list):
        return [s for v in x for s in strings_in(v)]
    if isinstance(x, dict):
        return [s for v in x.values() for s in strings_in(v)]
    return []


class TemplateTest(unittest.TestCase):
    def test_security_group_no_ingress_egress_all(self):
        _, sg = one("AWS::EC2::SecurityGroup")
        p = sg["Properties"]
        self.assertEqual(p.get("SecurityGroupIngress", []), [])
        self.assertEqual(len(p["SecurityGroupEgress"]), 1)
        self.assertEqual(str(p["SecurityGroupEgress"][0]["IpProtocol"]), "-1")
        self.assertFalse(of_type("AWS::EC2::SecurityGroupIngress"))

    def test_root_volume_encrypted_gp3_from_parameter(self):
        _, inst = one("AWS::EC2::Instance")
        bdm = inst["Properties"]["BlockDeviceMappings"]
        self.assertEqual(len(bdm), 1)
        self.assertEqual(bdm[0]["DeviceName"], {"Ref": "RootDeviceName"})     # must match the image (README.md)
        rd = T["Parameters"]["RootDeviceName"]
        self.assertEqual((rd["Default"], rd["AllowedValues"]), ("/dev/sda1", ["/dev/sda1", "/dev/xvda"]))
        ebs = bdm[0]["Ebs"]
        self.assertIs(ebs["Encrypted"], True)
        self.assertEqual(ebs["VolumeType"], "gp3")
        self.assertEqual(ebs["VolumeSize"], {"Ref": "VolumeGb"})

    def test_imdsv2_required(self):
        _, inst = one("AWS::EC2::Instance")
        self.assertEqual(inst["Properties"]["MetadataOptions"]["HttpTokens"], "required")

    def test_metadata_hop_limit_is_2(self):
        """2, so a container (the brain for Bedrock, the seeder for Route 53) can get the instance role's credentials;
        the scanner cannot, because its egress firewall rejects 169.254.0.0/16 (README.md, "Instance metadata")."""
        _, inst = one("AWS::EC2::Instance")
        mo = inst["Properties"]["MetadataOptions"]
        self.assertEqual(mo["HttpPutResponseHopLimit"], 2)
        self.assertEqual(mo["HttpEndpoint"], "enabled")
        with open(os.path.join(os.path.dirname(TEMPLATE), "..", "..", "scanner", "entrypoint.sh")) as fh:
            self.assertIn("probe iptables 169.254.169.254 169.254.0.0/16", fh.read(), "the scanner's metadata block and its start-up check")

    def test_no_key_name(self):
        _, inst = one("AWS::EC2::Instance")
        self.assertNotIn("KeyName", inst["Properties"])
        self.assertNotIn("KeyName", T.get("Parameters", {}))

    def test_role_has_ssm_core(self):
        role = R["InstanceRole"]["Properties"]
        self.assertIn("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore", role["ManagedPolicyArns"])
        self.assertEqual(R["InstanceProfile"]["Properties"]["Roles"], [{"Ref": "InstanceRole"}])

    def _inline_statements(self):
        out = []
        for res in of_type("AWS::IAM::Role").values():
            for pol in res["Properties"].get("Policies", []):
                out.extend(pol["PolicyDocument"]["Statement"])
        for res in of_type("AWS::IAM::Policy").values():
            out.extend(res["Properties"]["PolicyDocument"]["Statement"])
        return out

    def test_no_wildcard_action_or_resource(self):
        """No "*" in any action, and none in any resource string, including inside Fn::Sub, Fn::Join and Fn::Split.
        The one exception is route53:ListHostedZones, which has no resource type (the Service Authorization
        Reference lists none for it), so its statement can only name "*"."""
        stmts = self._inline_statements()
        self.assertTrue(stmts)
        for s in stmts:
            for a in as_list(s["Action"]):
                self.assertNotIn("*", a)
            if as_list(s["Action"]) == ["route53:ListHostedZones"]:
                self.assertEqual(s["Resource"], "*")
                continue
            for text in strings_in(s["Resource"]):
                self.assertNotIn("*", text, s.get("Sid"))

    def test_assume_role_only_the_seeder_role(self):
        sts = [s for s in self._inline_statements() if "sts:AssumeRole" in as_list(s["Action"])]
        self.assertEqual(len(sts), 1)
        self.assertEqual(as_list(sts[0]["Action"]), ["sts:AssumeRole"])
        self.assertEqual(sts[0]["Resource"], {"Ref": "SeederRoleArn"})
        # one role ARN, empty by default: the policy exists only when it is given
        self.assertEqual(T["Parameters"]["SeederRoleArn"]["Type"], "String")
        self.assertEqual(T["Parameters"]["SeederRoleArn"]["Default"], "")
        pol = R["SeederAssumeRolePolicy"]
        self.assertEqual(pol["Condition"], "HasSeederRole")
        self.assertEqual(pol["Properties"]["Roles"], [{"Ref": "InstanceRole"}])
        with open(TEMPLATE) as fh:
            self.assertIsNone(re.search(r"(?<!\d)\d{12}(?!\d)", fh.read()), "no account IDs in the template")

    def test_no_bucket_and_no_s3_permission(self):
        """Nothing in this project uses object storage, so the bucket and its permissions are gone."""
        self.assertFalse([k for k, v in R.items() if v["Type"].startswith("AWS::S3::")])
        self.assertFalse([s for s in self._inline_statements() if any(a.startswith("s3:") for a in as_list(s["Action"]))])
        self.assertNotIn("BucketName", T.get("Outputs", {}))

    def test_every_optional_permission_is_off_by_default(self):
        """With every parameter at its default, the instance role has the Session Manager policy and nothing else."""
        defaults = {k: v.get("Default") for k, v in T["Parameters"].items()}
        self.assertEqual((defaults["SeederRoleArn"], defaults["SeederHostedZoneIds"], defaults["BedrockAccess"]), ("", "", "none"))
        conds = {k: v["Condition"] for k, v in R.items() if v["Type"] == "AWS::IAM::Policy"}
        self.assertEqual(conds, {"SeederAssumeRolePolicy": "HasSeederRole", "SeederRoute53Policy": "HasSeederZones",
                                 "BedrockModelPolicy": "BedrockModel", "BedrockGlobalPolicy": "BedrockGlobal"})
        self.assertNotIn("Policies", R["InstanceRole"]["Properties"])

    def test_route53_permission_lists_zones_and_reads_only_the_named_zones(self):
        st = {s["Sid"]: s for s in R["SeederRoute53Policy"]["Properties"]["PolicyDocument"]["Statement"]}
        self.assertEqual(sorted(st), ["ListHostedZones", "ListRecordSetsOfNamedZones"])
        self.assertEqual(as_list(st["ListHostedZones"]["Action"]), ["route53:ListHostedZones"])
        self.assertEqual(as_list(st["ListRecordSetsOfNamedZones"]["Action"]), ["route53:ListResourceRecordSets"])
        text = " ".join(strings_in(st["ListRecordSetsOfNamedZones"]["Resource"]))
        self.assertIn("arn:aws:route53:::hostedzone/", text)
        self.assertIn("SeederHostedZoneIds", str(st["ListRecordSetsOfNamedZones"]["Resource"]))

    def test_bedrock_permission_is_invoke_model_on_one_model_only(self):
        """Converse needs bedrock:InvokeModel; nothing else (no streaming, no listing, no model management). The last
        statement of each policy is the provider check's read, tested below."""
        self.assertEqual(T["Parameters"]["BedrockAccess"]["AllowedValues"], ["none", "model", "global-profile"])
        model = R["BedrockModelPolicy"]["Properties"]["PolicyDocument"]["Statement"][:-1]
        glob = R["BedrockGlobalPolicy"]["Properties"]["PolicyDocument"]["Statement"][:-1]
        for s in model + glob:
            self.assertEqual(as_list(s["Action"]), ["bedrock:InvokeModel"])
            self.assertEqual(s["Effect"], "Allow")
        self.assertEqual(len(model), 1)
        self.assertIn("::foundation-model/${BedrockModelId}", " ".join(strings_in(model[0]["Resource"])))
        self.assertEqual([s["Sid"] for s in glob], ["GrantGlobalCrisInferenceProfileRegionAccess",
                                                     "GrantGlobalCrisInferenceProfileInRegionModelAccess",
                                                     "GrantGlobalCrisInferenceProfileGlobalModelAccess"])
        self.assertIn(":inference-profile/global.${BedrockModelId}", " ".join(strings_in(glob[0]["Resource"])))
        self.assertIn("arn:${AWS::Partition}:bedrock:::foundation-model/${BedrockModelId}", strings_in(glob[2]["Resource"]))
        for s in glob[1:]:   # the model ARNs only when called through this one profile
            self.assertIn("bedrock:InferenceProfileArn", s["Condition"]["StringEquals"])
        self.assertEqual(glob[2]["Condition"]["StringEquals"]["aws:RequestedRegion"], "unspecified")

    def test_the_provider_check_may_read_only_the_same_model_or_profile(self):
        """brain/tools/smoke_provider.py first calls GetFoundationModel (a model id) or GetInferenceProfile (a profile
        id). Each policy grants that one read, on the resource it may invoke, and nothing else."""
        model = R["BedrockModelPolicy"]["Properties"]["PolicyDocument"]["Statement"]
        glob = R["BedrockGlobalPolicy"]["Properties"]["PolicyDocument"]["Statement"]
        m, g = model[-1], glob[-1]
        self.assertEqual((m["Sid"], m["Effect"], as_list(m["Action"])), ("CheckOneFoundationModel", "Allow", ["bedrock:GetFoundationModel"]))
        self.assertEqual(m["Resource"], model[0]["Resource"])
        self.assertEqual((g["Sid"], g["Effect"], as_list(g["Action"])),
                         ("CheckTheGlobalInferenceProfile", "Allow", ["bedrock:GetInferenceProfile"]))
        self.assertEqual(g["Resource"], glob[0]["Resource"])
        self.assertEqual(g["Condition"], glob[0]["Condition"])
        actions = [a for s in model + glob for a in as_list(s["Action"])]
        self.assertEqual(sorted(set(actions)), ["bedrock:GetFoundationModel", "bedrock:GetInferenceProfile", "bedrock:InvokeModel"])

    def test_every_free_text_parameter_has_an_allowed_pattern(self):
        for name, p in T["Parameters"].items():
            if p["Type"] in ("String", "CommaDelimitedList") and "AllowedValues" not in p:
                self.assertIn("AllowedPattern", p, name)
                self.assertIn("ConstraintDescription", p, name)
        img = T["Parameters"]["ImageParameter"]
        self.assertEqual(img["Type"], "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>")
        self.assertIn(img["Default"], img["AllowedValues"])
        for v in img["AllowedValues"]:
            self.assertRegex(v, r"^/aws/service/canonical/ubuntu/server/24\.04/stable/current/(arm64|amd64)/hvm/ebs-gp3/ami-id$")

    def test_allowed_patterns_accept_and_refuse_what_they_should(self):
        P = {k: re.compile(v["AllowedPattern"]) for k, v in T["Parameters"].items() if "AllowedPattern" in v}
        cases = {
            "InstanceType": (["t4g.large", "t3.large", "m7g.xlarge"], ["t4g", "T4G.large", "t4g.large;x", ""]),
            "VpcCidr": (["172.24.96.0/24", "10.0.0.0/16"], ["10.0.0.0/8", "300.0.0.0/24", "10.0.0.0", "10.0.0.0/24 x"]),
            "AlarmEmail": (["", "ops@example.test"], ["not-an-email", "a@b", "a b@example.test"]),
            "ExistingAlarmTopicArn": (["", "arn:aws:sns:us-east-1:000000000000:alarms"], ["arn:aws:sns:us-east-1:1:x", "topic"]),
            "SeederRoleArn": (["", "arn:aws:iam::000000000000:role/dns-read"],
                              ["arn:aws:iam::000000000000:user/x", "arn:aws:iam::0:role/x", "role/x"]),
            "SeederHostedZoneIds": (["", "Z0123456789ABCDEFGHIJ"], ["z1", "Z1/x", "*"]),
            "BedrockModelId": (["", "provider.model-name-v1:0"], ["global.x y", "Provider.Model", "*"]),
            "BedrockRegion": (["", "us-east-1", "eu-central-2"], ["us_east_1", "us-east", "*"]),
        }
        self.assertEqual(sorted(P), sorted(cases))
        for name, (good, bad) in cases.items():
            for v in good:
                self.assertTrue(P[name].fullmatch(v), (name, v))
            for v in bad:
                self.assertFalse(P[name].fullmatch(v), (name, v))

    def test_user_data_installs_docker_and_compose_only(self):
        _, inst = one("AWS::EC2::Instance")
        ud = inst["Properties"]["UserData"]["Fn::Base64"]
        installs = re.findall(r"apt-get install (.*)", ud)
        self.assertEqual(installs, ["-y --no-install-recommends docker.io docker-buildx docker-compose-v2"])
        for absent in ("git", "clone", "curl", "wget", "| sh", "|sh", "docker compose up", "pip"):
            self.assertNotIn(absent, ud)

    def test_static_outbound_address_and_no_public_address_on_launch(self):
        _, eip = one("AWS::EC2::EIP")
        self.assertEqual(eip["Properties"]["Domain"], "vpc")
        _, assoc = one("AWS::EC2::EIPAssociation")
        self.assertEqual(assoc["Properties"]["InstanceId"], {"Ref": "ScannerInstance"})
        _, sub = one("AWS::EC2::Subnet")
        self.assertIs(sub["Properties"]["MapPublicIpOnLaunch"], False)

    def test_dlm_keep_7_target_backup_tag(self):
        _, dlm = one("AWS::DLM::LifecyclePolicy")
        d = dlm["Properties"]["PolicyDetails"]
        self.assertEqual(d["TargetTags"], [{"Key": "Backup", "Value": "scan"}])
        self.assertEqual(d["Schedules"][0]["RetainRule"]["Count"], 7)
        _, inst = one("AWS::EC2::Instance")
        self.assertIn({"Key": "Backup", "Value": "scan"}, inst["Properties"]["Tags"])

    def test_dlm_description_charset(self):
        _, dlm = one("AWS::DLM::LifecyclePolicy")
        self.assertRegex(dlm["Properties"]["Description"], r"^[0-9A-Za-z _-]+$")

    def test_alarm_actions_reference_topic(self):
        _, alarm = one("AWS::CloudWatch::Alarm")
        p = alarm["Properties"]
        self.assertEqual(p["MetricName"], "StatusCheckFailed")
        self.assertEqual((p["Period"], p["EvaluationPeriods"], p["TreatMissingData"]), (300, 2, "breaching"))
        self.assertEqual(p["AlarmActions"], [{"Fn::If": ["CreateTopic", {"Ref": "AlarmTopic"}, {"Ref": "ExistingAlarmTopicArn"}]}])
        self.assertEqual(R["AlarmTopic"]["Type"], "AWS::SNS::Topic")


if __name__ == "__main__":
    unittest.main()
