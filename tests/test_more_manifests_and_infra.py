"""Extended tests for PHP, Ruby, .NET, Kubernetes, Ansible, CloudFormation, Vercel, etc."""

from pathlib import Path

from app_stack_finder.core.models import TechCategory
from app_stack_finder.detectors.infra_detector import InfraDetector
from app_stack_finder.detectors.manifest_detector import ManifestDetector


def test_php_and_ruby_manifests(tmp_path: Path):
    composer = tmp_path / "composer.json"
    composer.write_text("""{
        "require": {
            "php": "^8.2",
            "laravel/framework": "^10.10",
            "doctrine/orm": "^2.16"
        }
    }""")

    gemfile = tmp_path / "Gemfile"
    gemfile.write_text("""
source 'https://rubygems.org'
ruby '3.3.0'
gem 'rails', '~> 7.1.3'
gem 'sidekiq', '7.2.0'
""")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [composer, gemfile])
    names = {item.name: item for item in results}

    assert "PHP" in names
    assert names["PHP"].version == "8.2"
    assert "Laravel" in names
    assert names["Laravel"].version == "10.10"
    assert "Doctrine ORM" in names

    assert "Ruby" in names
    assert names["Ruby"].version == "3.3.0"
    assert "Ruby on Rails" in names
    assert names["Ruby on Rails"].version == "7.1.3"
    assert "Sidekiq" in names
    assert names["Sidekiq"].version == "7.2.0"


def test_dotnet_manifests(tmp_path: Path):
    csproj = tmp_path / "WebApi.csproj"
    csproj.write_text("""<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.OpenApi" Version="8.0.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="8.0.0" />
  </ItemGroup>
</Project>""")

    detector = ManifestDetector()
    results = detector.detect_filesystem(tmp_path, [csproj])
    names = {item.name: item for item in results}

    assert "C#" in names
    assert ".NET" in names
    assert names[".NET"].version == "8.0"
    assert "ASP.NET Core" in names
    assert "Entity Framework Core" in names


def test_k8s_ansible_cloudformation_vercel(tmp_path: Path):
    k8s_yaml = tmp_path / "deployment.yaml"
    k8s_yaml.write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 3
""")

    ansible_cfg = tmp_path / "ansible.cfg"
    ansible_cfg.write_text("[defaults]\ninventory = ./hosts\n")

    cfn_tmpl = tmp_path / "template.yaml"
    cfn_tmpl.write_text("""AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: An AWS Serverless Application
""")

    vercel_json = tmp_path / "vercel.json"
    vercel_json.write_text('{"framework": "nextjs"}')

    detector = InfraDetector()
    results = detector.detect_filesystem(tmp_path, [k8s_yaml, ansible_cfg, cfn_tmpl, vercel_json])
    names = {item.name: item for item in results}

    assert "Kubernetes" in names
    assert "Ansible" in names
    assert "AWS CloudFormation" in names
    assert "Vercel" in names
