from kit.testing import run_policy

FILE = "examples/policies/sg-ssh-open.yaml"
NAME = "sg-ssh-open-to-world"


def _resources():
    return [
        {
            "GroupId": "sg-open",
            "OwnerId": "111111111111",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        },
        {
            "GroupId": "sg-restricted",
            "OwnerId": "111111111111",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                }
            ],
        },
        {"GroupId": "sg-no-rules", "OwnerId": "111111111111", "IpPermissions": []},
    ]


def test_matches_only_the_one_open_to_the_internet():
    matched = run_policy(FILE, NAME, _resources())
    assert [r["GroupId"] for r in matched] == ["sg-open"]
